import os

# CRITICAL: Mandatory environment variables for production security
SECRET_KEY = os.environ["NETVISOR_SECRET_KEY"]
AGENT_API_KEY = os.environ["AGENT_API_KEY"]


# Default State
# State is now managed in core.state

