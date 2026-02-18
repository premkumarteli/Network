import requests

BASE_URL = "http://127.0.0.1:8000"
session = requests.Session()

# Log in
print("Attempting to log in...")
login_res = session.post(f"{BASE_URL}/login", data={"username": "admin", "password": "pppp"}, allow_redirects=True)
print(f"Login Response Status: {login_res.status_code}")

# Fetch activity
print("Fetching activity logs metadata...")
r = session.get(f"{BASE_URL}/api/activity")
if r.status_code == 200:
    logs = r.json()
    if logs:
        for entry in logs[:5]: # Show top 5
            print(f"[{entry['time']}] {entry['ip']} -> {entry['domain']}")
            print(f"   - Metadata: OS={entry['os']}, Brand={entry['brand']}, Device={entry['device']}")
    else:
        print("No logs found. Ensure the agent is running and sending traffic.")
else:
    print(f"Failed to fetch logs. Status: {r.status_code}")
