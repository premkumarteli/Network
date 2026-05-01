# Runbook

This is the operational cheat sheet for NetVisor.

## Startup Order

1. Start the database.
2. Start `python run_server.py`.
3. Start `python run_gateway.py` if you need BYOD metadata collection.
4. Start `python run_agent.py` on managed endpoints.

## Health Checks

- `python run_server.py --health-check`
- `python run_agent.py --health-check`
- `python run_gateway.py --health-check`

Backend health endpoints:

- `/api/v1/health/ready`
- `/api/v1/health/status`
- `/api/v1/health/metrics`

## Common Recovery Paths

- If the agent or gateway refuses to enroll, reset the local enrollment state and restart the process.
- If the backend says a credential is missing or invalid, restart `run_server.py` so the live API process picks up the latest code.
- If browser evidence looks stale, verify that the managed-device inspection policy is enabled and the local proxy launcher is being used.
- If flow data looks incomplete, confirm that the flow worker is running and the queue health metrics are clean.

## Generated Output

- Runtime state belongs under `runtime/`.
- Release bundles belong under `build/deploy/`.
- Do not commit generated bundles, caches, or package-manager output.

## Troubleshooting Checklist

- Check `X-Request-ID` in logs and responses.
- Verify database connectivity first.
- Confirm `AGENT_API_KEY` and `GATEWAY_API_KEY` are aligned with the backend.
- Confirm the backend TLS pinset before enrolling a non-local agent or gateway.
- Use the deployment manifests in `deployment/` for the canonical production settings.
