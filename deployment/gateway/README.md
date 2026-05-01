# Gateway Deployment Manifest

Deploy these paths to the gateway machine:

- `gateway/`
- `shared/`
- `requirements-gateway.txt`
- `.env`
- `run_gateway.py`
- `scripts/run_gateway.py`

Preferred packaging flow:

- `python scripts/build_deploy_bundles.py --role gateway`
- deploy the generated `build/deploy/gateway/` folder as the gateway runtime root
- install dependencies with `python -m pip install -r requirements.txt`

Linux service packaging:

- the generated bundle includes `systemd/netvisor-gateway.service`
- copy it to `/etc/systemd/system/netvisor-gateway.service`
- set the `WorkingDirectory` and `EnvironmentFile` paths if you deploy outside `/opt/netvisor/gateway`
- create the `netvisor-gateway` user/group, then run `systemctl enable --now netvisor-gateway`

Gateway responsibilities:

- capture network traffic that actually passes through the gateway host
- aggregate metadata-only flows
- upload BYOD-safe flow data to the backend
- support `--health-check` for probe mode and supervision

Machine-specific setup:

- set `NETVISOR_SERVER_URL` to the server IP or DNS name
- use `https://` for any non-local backend URL
- set `GATEWAY_API_KEY` in `.env`; it is now bootstrap-only and is used only by `POST /api/v1/gateway/register`
- set `NETVISOR_GATEWAY_CAPTURE_BACKEND=auto` for Linux-native capture preference or `scapy` to force the fallback backend
- set `NETVISOR_GATEWAY_CAPTURE_INTERFACE` when you want to pin capture to a specific NIC
- set `NETVISOR_PACKET_TRACE=false` unless you need packet-level console tracing while debugging capture
- tune `NETVISOR_FLOW_FLUSH_INTERVAL_SECONDS`, `NETVISOR_FLOW_CLEANUP_INTERVAL_SECONDS`, and `NETVISOR_FLOW_MAX_ACTIVE_FLOWS` if you need different throughput / memory tradeoffs
- seed `NETVISOR_BACKEND_TLS_PINS_JSON` in `.env` before first contact with any non-local backend
- run with packet-capture support installed
- run with administrative privileges when required by the OS
- use it as the real hotspot / NAT / mirror point, not just a machine on the same LAN
- do not copy another machine's `runtime/gateway` directory; the gateway now persists its signed credential and pinset locally
- if a gateway loses its local signed credential state, re-registering will not reissue the active secret; use the explicit rotation flow or re-enroll the gateway
- `python run_gateway.py --health-check` prints a local readiness snapshot without starting packet capture
- `python run_gateway.py --reset-enrollment` clears the stored signed credential and preserves the local pinset so you can re-enroll cleanly
