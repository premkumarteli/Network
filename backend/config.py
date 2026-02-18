import os
import time

# CRITICAL: Mandatory environment variables for production security
SECRET_KEY = os.environ["NETVISOR_SECRET_KEY"]
AGENT_API_KEY = os.environ["AGENT_API_KEY"]
START_TIME = time.time()

# Default State
MAINTENANCE_MODE = False
MONITORING_ACTIVE = True
HOTSPOT_ACTIVE = False
