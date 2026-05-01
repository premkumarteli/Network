# NetVisor Security Operations Runbook

## Scope

This runbook covers the Phase 3 and Phase 4 operational controls now enforced by the backend:

- signed agent authentication with replay protection
- signed gateway authentication with replay protection
- HTTPS-only remote collection traffic
- backend TLS pin publication to agents and gateways
- rate limiting on auth, admin mutation, and agent collection endpoints
- health and metrics visibility for queue pressure, auth failures, capture backend lag, and inspection spool activity
- request tracing with `X-Request-ID`
- release metadata and backup verification surfaced through health endpoints
- migration-backed runtime schema readiness checks
- DPI inspection is disabled by default and must be enabled explicitly per managed device by policy
- the DPI path enforces a privacy guard that bypasses sensitive destinations even when they are otherwise reachable
- certificate status now reports `days_until_expiry`, `days_until_rotation_due`, `expires_soon`, and `rotation_due_soon`

## HTTPS Setup For Remote Agents

1. Terminate TLS directly on the NetVisor backend or on a reverse proxy in front of it.
2. Ensure the public certificate chain validates normally with the system trust store.
3. Publish the backend pin set in `NETVISOR_BACKEND_TLS_PINS_JSON` on the server and seed the same pin set in the agent or gateway `.env` before first non-local contact.
4. Verify remote agents and gateways use an `https://` backend URL.

## Reverse Proxy Deployment

1. Build the server bundle with `python scripts/build_deploy_bundles.py --role server`.
2. In the generated server bundle, copy `.env.example` to `.env`.
3. Set:
   - `NETVISOR_PUBLIC_HOSTNAME` to the DNS hostname that will terminate HTTPS
   - `NETVISOR_TRUST_PROXY_HEADERS=true`
   - `NETVISOR_FORWARDED_ALLOW_IPS=*` only when the API is reachable only through the internal compose network
4. Run `docker compose up -d` from the server bundle root.
5. Confirm the reverse proxy is the only public entrypoint. The internal API container should not publish port `8000` directly to the internet.

If you replace Caddy with another reverse proxy or load balancer, keep the same security boundary:

- HTTPS terminates at the proxy
- the proxy forwards `X-Forwarded-*` headers
- the API only trusts forwarded headers from known proxy addresses
- agents and gateways pin the public TLS certificate key, not an internal cleartext hop

## Browser Session Protection

1. Browser auth uses an `httpOnly` session cookie.
2. Browser mutating requests must include the `X-XSRF-TOKEN` header.
3. The header value must match the `XSRF-TOKEN` cookie value.
4. Frontend Axios is configured to send that pair automatically for same-origin or credentialed requests.

Recommended pin format:

```json
[
  {
    "pin_type": "spki_sha256",
    "pin_sha256": "REPLACE_WITH_UPPERCASE_64_CHAR_SHA256",
    "status": "active",
    "subject": "CN=netvisor.example"
  }
]
```

## Pin Rotation Procedure

1. Generate the new backend certificate and compute the next pin.
2. Add the new pin to `NETVISOR_BACKEND_TLS_PINS_JSON` with `"status": "next"`.
3. Restart the backend so `/api/v1/collect/*` responses publish both the active and next pins.
4. Allow agents and gateways to refresh their stored pin set through heartbeat / bootstrap.
5. Deploy the new backend certificate.
6. Promote the new pin to `"active"` and remove the old pin after agents and gateways have refreshed.

## Agent Re-enrollment / Credential Recovery

Use this only if an agent lost its DPAPI-protected local credential state.

1. Stop the affected agent.
2. Use the explicit signed rotation flow when possible.
3. If the local signed credential is gone and signed rotation is not possible, remove the local agent runtime security state and re-enroll:
   - `runtime/agent/security/agent_transport_state.dpapi`
   - only on the affected machine
4. Start the agent and confirm `/api/v1/health/status` shows signed auth successes increasing.

Do not use `/api/v1/collect/register` as a credential recovery path for an already-enrolled agent. It no longer returns the active signing secret.

The managed-device DPI proxy no longer uses `--ssl-insecure` in production mode. If a browser inspection flow starts failing because upstream TLS verification now blocks a destination, treat that as a policy or trust-root problem to resolve explicitly, not as a flag to re-enable.
Sensitive destinations such as banking, identity, and payment sites are always bypassed by the DPI policy and should not be added to the allow list.

## Gateway Re-enrollment / Credential Recovery

Use this only if a gateway lost its local signed credential state.

1. Stop the affected gateway.
2. If the gateway still has its signed credential, call `POST /api/v1/gateway/rotate-credential` while authenticated as that gateway.
3. If the local signed credential is gone and rotation is not possible, remove the local gateway runtime security state on the affected machine only:
   - `runtime/gateway/security/gateway_transport_state.secure`
4. Start the gateway and confirm `POST /api/v1/gateway/register` succeeds.
5. If the backend responds with `gateway_credentials: null`, the gateway was already enrolled and needs an explicit re-enrollment / credential reset by an operator before it can resume signed uploads.

## Metrics And Observability

Use these endpoints:

- `GET /api/v1/health/status`
- `GET /api/v1/health/ready`
- `GET /api/v1/health/metrics`
- `GET /api/v1/health/metrics.prom`

Key indicators:

- `flow_queue_depth`
- `flow_oldest_pending_age_seconds`
- `flow_active_workers`
- `flow_backpressure_rejections_total`
- `flow_dropped_flows_total`
- `flow_failed_batches_total`
- agent or gateway `capture` snapshots showing active backend, lag, packets seen, packets emitted, and packets dropped
- `http_requests_total`
- `http_request_duration_seconds`
- `agent_auth_failures_total`
- `gateway_auth_failures_total`
- `gateway_bootstrap_auth_success_total`
- `gateway_bootstrap_auth_failures_total`
- `transport_https_rejections_total`
- backup verification status from `/api/v1/system/status`
- release metadata from `/api/v1/health/status` and `/api/v1/system/release`
- inspection spool totals from agent-reported metrics
- `/api/v1/health/status` `runtime_schema_ready`
- `/api/v1/health/ready` `runtime_schema`

## Rate Limit Defaults

Server-side defaults:

- login: `20/min`
- self-register: `5/min`
- agent bootstrap: `30/min`
- agent control endpoints: `240/min`
- flow ingest: `1200/min`
- admin mutations: `30/min`

Tune only after measuring real traffic patterns.
