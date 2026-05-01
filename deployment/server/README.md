# Server Deployment Manifest

Preferred packaging flow:

- `python scripts/build_deploy_bundles.py --role server`
- deploy the generated `build/deploy/server/` folder as the server runtime root
- copy `.env.example` to `.env` in the bundle root and set the production values
- run `docker compose up -d` from the bundle root

The generated bundle contains:

- `app/`
- `shared/`
- `database/`
- `frontend/dist/`
- `requirements.txt`
- `run_server.py`
- `run_flow_worker.py`
- `run_backup_retention.py`
- `.env.example`
- `docker-compose.yml`
- `Caddyfile`
- `systemd/netvisor-backup-retention.service`
- `systemd/netvisor-backup-retention.timer`

Probe mode:

- `python run_server.py --health-check` prints a startup/readiness snapshot and exits with status 0 after the server boots successfully

Server responsibilities:

- host the FastAPI API
- serve the built React UI from `frontend/dist`
- apply versioned migrations before the app starts
- run the durable flow worker as a separate runtime
- receive agent and gateway uploads through a TLS reverse proxy

Minimum server env:

- `NETVISOR_PUBLIC_HOSTNAME`
- `NETVISOR_SECRET_KEY`
- `NETVISOR_AGENT_MASTER_KEY`
- `NETVISOR_GATEWAY_MASTER_KEY`
- `NETVISOR_DB_PASSWORD`
- `NETVISOR_DB_NAME`
- `NETVISOR_BOOTSTRAP_ADMIN_PASSWORD`
- `AGENT_API_KEY`
- `GATEWAY_API_KEY`
- `NETVISOR_BACKUP_RETENTION_DAYS`

Notes:

- `deployment/server/docker-compose.yml` is a bundle template. Use it from the generated bundle root, not directly from the repo.
- the bundle compose only mounts canonical runtime paths. Archived snapshot content is not part of the active deployment surface.
- the bundle builder will generate `frontend/dist/` if it is missing. Build it locally with `npm run build` in `frontend/` if you want to avoid bundle-time frontend compilation.
- the `migrate` service runs `apply_20260416_gateway_security_phase1.py`, `apply_20260417_runtime_schema_phase2.py`, `apply_20260418_flow_ingest_phase3.py`, and `apply_20260419_flow_ingest_hardening_phase4.py` before the API starts. App code no longer patches runtime tables, columns, or indexes on the fly.
- the `flow_worker` service drains durable flow batches from MySQL. The API container runs with `NETVISOR_FLOW_WORKER_MODE=disabled` in the compose deployment path so ingest and persistence are separated.
- tune `NETVISOR_FLOW_INGEST_MAX_PENDING_FLOWS`, `NETVISOR_FLOW_INGEST_MAX_LAG_SECONDS`, `NETVISOR_FLOW_WORKER_HEARTBEAT_SECONDS`, and `NETVISOR_FLOW_WORKER_ALIVE_SECONDS` if you need different queue SLOs.
- tune `NETVISOR_PACKET_TRACE`, `NETVISOR_FLOW_FLUSH_INTERVAL_SECONDS`, `NETVISOR_FLOW_CLEANUP_INTERVAL_SECONDS`, and `NETVISOR_FLOW_MAX_ACTIVE_FLOWS` if you need different packet-path throughput behavior.
- `NETVISOR_FLOW_QUEUE_STATUS_CACHE_SECONDS` controls how often queue depth counters are refreshed from MySQL instead of using the in-process cache.
- run `python run_backup_retention.py` on a schedule or enable the bundled `systemd/netvisor-backup-retention.timer` to prune expired backup directories, and override `NETVISOR_BACKUP_RETENTION_DAYS` if you need a different retention window.
- the `reverse_proxy` service terminates HTTPS at Caddy and forwards traffic to the internal API container. `run_server.py` now trusts forwarded headers only when `NETVISOR_TRUST_PROXY_HEADERS=true`.
- browser auth now uses an `httpOnly` session cookie, and browser mutating requests must send the `X-XSRF-TOKEN` header that matches the `XSRF-TOKEN` cookie. Keep `NETVISOR_AUTH_COOKIE_SECURE=true` in this HTTPS deployment path.
- request tracing uses `X-Request-ID`; the health surface also exposes release metadata and backup verification status.
- DPI inspection is disabled by default and must be enabled explicitly per managed device through policy.
- `/api/v1/system/status` returns runtime, release, and backup state; `/api/v1/system/release` returns the release-only view.
- set `NETVISOR_PUBLIC_HOSTNAME` to a real DNS hostname. Automatic HTTPS from Caddy will not work against a raw IP address.
- treat `GATEWAY_API_KEY` as a bootstrap-only secret. Heartbeats and flow uploads now require signed gateway credentials.
- publish backend TLS pins through `NETVISOR_BACKEND_TLS_PINS_JSON` before enrolling non-local agents or gateways.
- use `/api/v1/health/status`, `/api/v1/health/ready`, and `/api/v1/health/metrics` to verify security schema readiness, runtime schema readiness, flow queue health, signed-auth failures, gateway bootstrap activity, and inspection spool visibility after deployment.
- see `docs/security_operations.md` for HTTPS setup, pin rotation, agent/gateway re-enrollment, and operator guidance.
