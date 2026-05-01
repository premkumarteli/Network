# Deployment Layout

NetVisor deploys as three runtimes:

- `server`: backend API, database, and built frontend
- `agent`: managed endpoint collector and DPI runtime
- `gateway`: metadata-only network collector for BYOD visibility

This folder contains role-specific manifests so each runtime can be copied to a
different machine without guessing which files belong together.

Bundle builder:

- `python scripts/build_deploy_bundles.py`
- output defaults to `build/deploy/`
- use `--role server`, `--role agent`, or `--role gateway` to build only one bundle

Small-install local stack:

- `deployment/docker-compose.yml` now mounts only canonical runtime assets from the current repo layout
- it runs MySQL, a one-shot migration service, the FastAPI server from `app/`, and a separate durable flow worker
- the server bundle will build `frontend/dist/` on demand if the UI bundle is missing; prebuild it manually if you want a fully offline bundle step
- from the repo root, start it with `docker compose --env-file .env -f deployment/docker-compose.yml up -d`

Server production bundle:

- `deployment/server/docker-compose.yml` is copied into the generated server bundle as `docker-compose.yml`
- the bundle compose runs MySQL, explicit migrations, the FastAPI server, a separate durable flow worker, and a Caddy reverse proxy for HTTPS
- the generated server bundle also includes `run_backup_retention.py` plus a `systemd/` timer pair for scheduled backup pruning
- `deployment/server/Caddyfile` is copied into the bundle root as `Caddyfile`
- the server bundle exposes `/api/v1/system/status` for runtime/release/backup state and `/api/v1/system/release` for release-only checks

Each generated bundle includes:

- only the runtime code required for that role
- a role-local `requirements.txt`
- a role-local `.env.example`
- a role-local `README.md`

The bundle builder does not copy:

- `runtime/`
- `tmp/`
- `tests/`
- archived code is not part of the active deployment surface
- source-only frontend files under `frontend/src/`
