import os
import time

SECRET_KEY = os.getenv("NETVISOR_SECRET_KEY", "change-me-in-env")
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "soc-agent-key-2026")
START_TIME = time.time()

# Default State
MAINTENANCE_MODE = False
MONITORING_ACTIVE = True
HOTSPOT_ACTIVE = False
