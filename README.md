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
|- legacy/                 # archived pre-MVP code
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
- `python scripts/run_agent.py`
- `python scripts/run_gateway.py`

Convenience wrappers:

- `python run_server.py`
- `python run_agent.py`
- `python run_gateway.py`

## Environment

Copy `.env.example` to `.env` and set at least:

- `NETVISOR_SECRET_KEY`
- `NETVISOR_DB_HOST`
- `NETVISOR_DB_USER`
- `NETVISOR_DB_PASSWORD`
- `NETVISOR_DB_NAME`
- `NETVISOR_BOOTSTRAP_ADMIN_PASSWORD`
- `AGENT_API_KEY`
- `GATEWAY_API_KEY`

Optional runtime tuning:

- `NETVISOR_AGENT_HEARTBEAT_SECONDS`
- `NETVISOR_GATEWAY_HEARTBEAT_SECONDS`
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
- The backend API root is `/api/v1`.
- Device status is derived from `last_seen`, not from ping:
  - `Online` < 10 seconds
  - `Idle` < 60 seconds
  - `Offline` otherwise
- Application sessions are derived from flow segments and refresh every few
  seconds after agent/gateway activity arrives.
