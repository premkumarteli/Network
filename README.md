# NetVisor

NetVisor is a self-hosted network threat detection platform for mixed device
environments:

- managed endpoints send deeper flow data through the local agent
- BYOD traffic is observed through the metadata-only gateway
- the backend scores activity and serves the React SOC dashboard

## Canonical Layout

```text
Network/
|- app/                    # FastAPI backend package
|  |- api/                 # HTTP route handlers
|  |- core/                # settings, auth, shared dependencies
|  |- db/                  # DB connection/bootstrap
|  |- ml/                  # ML model runtime
|  |- schemas/             # request/response schemas
|  |- services/            # business logic and detectors
|  |- main.py              # backend ASGI entrypoint
|  `- realtime.py          # Socket.IO wiring
|- agent/                  # managed-device agent
|- gateway/                # gateway packet collector
|- config/                 # checked-in runtime config
|- database/               # schema bootstrap SQL
|- deployment/             # deployment assets
|- docs/                   # product and architecture specs
|- frontend/               # React/Vite UI
|- shared/                 # runtime code shared by agent and gateway
|- runtime/                # generated runtime state and backups
|- scripts/                # canonical startup scripts
|- tests/                  # automated tests
|- run_server.py           # convenience launcher
|- run_agent.py            # convenience launcher
`- run_gateway.py          # convenience launcher
```

## Entry Points

Preferred:

- `python scripts/run_server.py`
- `python run_server.py --health-check`
- `python scripts/run_flow_worker.py`
- `python scripts/run_backup_retention.py`
- `python scripts/run_agent.py`
- `python scripts/run_gateway.py`

Role deployment manifests:

- `deployment/server/README.md`
- `deployment/agent/README.md`
- `deployment/gateway/README.md`

Bundle builder:

- `python scripts/build_deploy_bundles.py`
- generated bundles land under `build/deploy/`
- each bundle contains a role-local `requirements.txt`, `.env.example`, and `README.md`
- the server bundle also includes `docker-compose.yml` and `Caddyfile` for HTTPS deployment
- the server bundle will build `frontend/dist/` on demand if the UI bundle is missing

Convenience wrappers:

- `python run_server.py`
- `python run_flow_worker.py`
- `python run_backup_retention.py`
- `python run_agent.py --reset-enrollment`
- `python run_gateway.py --reset-enrollment`
- `python run_agent.py`
- `python run_gateway.py`

## Environment

Copy `.env.example` to `.env` and set at least:

- `NETVISOR_AGENT_MASTER_KEY`
- `NETVISOR_GATEWAY_MASTER_KEY`
- `NETVISOR_SECRET_KEY`
- `NETVISOR_DB_HOST`
- `NETVISOR_DB_USER`
- `NETVISOR_DB_PASSWORD`
- `NETVISOR_DB_NAME`
- `NETVISOR_BOOTSTRAP_ADMIN_PASSWORD`
- `AGENT_API_KEY`
- `GATEWAY_API_KEY`

For reverse-proxied deployments also set:

- `NETVISOR_PUBLIC_HOSTNAME`
- `NETVISOR_TRUST_PROXY_HEADERS`
- `NETVISOR_FORWARDED_ALLOW_IPS`

Browser auth defaults:

- the React app now uses same-origin `/api/v1` by default
- browser sessions are stored in an `httpOnly` auth cookie, not `localStorage`
- browser mutating requests use the `XSRF-TOKEN` cookie plus `X-XSRF-TOKEN` header for CSRF protection
- every HTTP response includes an `X-Request-ID` header for traceability
- local development should keep `NETVISOR_AUTH_COOKIE_SECURE=false`
- HTTPS deployments should set `NETVISOR_AUTH_COOKIE_SECURE=true`

Optional runtime tuning:

- `NETVISOR_AGENT_HEARTBEAT_SECONDS`
- `NETVISOR_GATEWAY_HEARTBEAT_SECONDS`
- `NETVISOR_CAPTURE_BACKEND`
- `NETVISOR_CAPTURE_INTERFACE`
- `NETVISOR_AGENT_CAPTURE_BACKEND`
- `NETVISOR_AGENT_CAPTURE_INTERFACE`
- `NETVISOR_GATEWAY_CAPTURE_BACKEND`
- `NETVISOR_GATEWAY_CAPTURE_INTERFACE`
- `NETVISOR_PACKET_TRACE`
- `NETVISOR_FLOW_FLUSH_INTERVAL_SECONDS`
- `NETVISOR_FLOW_CLEANUP_INTERVAL_SECONDS`
- `NETVISOR_FLOW_MAX_ACTIVE_FLOWS`
- `NETVISOR_FLOW_QUEUE_STATUS_CACHE_SECONDS`
- `NETVISOR_FLOW_WORKER_HEARTBEAT_SECONDS`
- `NETVISOR_FLOW_WORKER_ALIVE_SECONDS`
- `NETVISOR_FLOW_INGEST_MAX_PENDING_FLOWS`
- `NETVISOR_FLOW_INGEST_MAX_LAG_SECONDS`
- `NETVISOR_BACKUP_RETENTION_DAYS`
- `NETVISOR_RESET_RUNTIME_ON_STARTUP`
- `NETVISOR_BACKUP_AND_RESET_ON_SHUTDOWN`

## Database Setup

Create or rebuild the schema:

```powershell
mysql -u root -p < database\init.sql
```

## Development Checks

Backend tests:

```powershell
python -m pytest -q -p no:cacheprovider
```

Frontend lint/build:

```powershell
cd frontend
npm run lint
npm run build
```

## Runtime Notes

- Local runtime state is written under `runtime/`.
- Runtime backups are exported as CSV under `runtime/backups/server/`.
- `run_backup_retention.py` prunes expired backup directories according to `NETVISOR_BACKUP_RETENTION_DAYS`.
- Backup verification status and release metadata are exposed through `/api/v1/system/status` and `/api/v1/system/release`.
- The backend API root is `/api/v1`.
- Packet capture is now pluggable: Linux-native raw socket capture is preferred when configured (`auto` on Linux or `linux_raw` explicitly), with Scapy as the fallback backend.
- durable flow ingestion now lands in a DB-backed queue; production deployments should run the dedicated flow worker instead of depending on the API process alone
- flow batches are deduplicated by deterministic `batch_id`, rejected under configured backpressure, and tracked with worker heartbeat / lag metrics
- archived code has been removed from the active tree; recover anything historical from git history rather than runtime paths.
- Device status is derived from `last_seen`, not from ping:
  - `Online` < 10 seconds
  - `Idle` < 60 seconds
  - `Offline` otherwise
- Application sessions are derived from flow segments and refresh every few
  seconds after agent/gateway activity arrives.
