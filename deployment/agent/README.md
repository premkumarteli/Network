# Agent Deployment Manifest

Deploy these paths to each managed endpoint:

- `agent/`
- `shared/`
- `config/agent.json`
- `requirements-agent.txt`
- `.env`
- `run_agent.py`
- `scripts/run_agent.py`

Preferred packaging flow:

- `python scripts/build_deploy_bundles.py --role agent`
- deploy the generated `build/deploy/agent/` folder as the agent runtime root
- install dependencies with `python -m pip install -r requirements.txt`

Linux service packaging:

- the generated bundle includes `systemd/netvisor-agent.service`
- copy it to `/etc/systemd/system/netvisor-agent.service`
- set the `WorkingDirectory` and `EnvironmentFile` paths if you deploy outside `/opt/netvisor/agent`
- create the `netvisor-agent` user/group, then run `systemctl enable --now netvisor-agent`

Agent responsibilities:

- register the managed device with the backend
- capture managed-device traffic and enrich it with endpoint context
- run the optional DPI / explicit proxy workflow locally
- support `--health-check` for probe mode and supervision

Machine-specific setup:

- change `config/agent.json` `server_url` to the server IP or DNS name
- set `AGENT_API_KEY` in `.env`
- set `NETVISOR_AGENT_CAPTURE_BACKEND=auto` for Linux-native capture preference or `scapy` to force the fallback backend
- set `NETVISOR_AGENT_CAPTURE_INTERFACE` when you want to pin capture to a specific NIC
- set `NETVISOR_PACKET_TRACE=false` unless you need packet-level console tracing while debugging capture
- tune `NETVISOR_FLOW_FLUSH_INTERVAL_SECONDS`, `NETVISOR_FLOW_CLEANUP_INTERVAL_SECONDS`, and `NETVISOR_FLOW_MAX_ACTIVE_FLOWS` if you need different throughput / memory tradeoffs
- use `https://` for any non-local backend URL
- set `NETVISOR_BACKEND_TLS_PINS_JSON` in `.env` before first contact with a non-local backend
- do not copy another machine's `runtime/agent` directory
- let the agent create fresh DPAPI-protected local state on first start
- follow `docs/security_operations.md` for backend pin rotation and agent re-enrollment procedures
- `python run_agent.py --health-check` prints a local readiness snapshot without starting packet capture
- `python run_agent.py --reset-enrollment` clears the stored signed credential and preserves the local pinset so you can re-enroll cleanly

Optional helper:

- `scripts/launch_personal_chrome_dpi.cmd` launches Chrome against the local explicit proxy for DPI testing
