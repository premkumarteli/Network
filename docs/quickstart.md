# Quick Start

This is the shortest path to a working local NetVisor stack.

## 1. Configure

Copy `.env.example` to `.env` and set at least:

- `NETVISOR_SECRET_KEY`
- `NETVISOR_AGENT_MASTER_KEY`
- `NETVISOR_GATEWAY_MASTER_KEY`
- `NETVISOR_DB_HOST`
- `NETVISOR_DB_USER`
- `NETVISOR_DB_PASSWORD`
- `NETVISOR_DB_NAME`
- `NETVISOR_BOOTSTRAP_ADMIN_PASSWORD`
- `AGENT_API_KEY`
- `GATEWAY_API_KEY`

If you are running behind a reverse proxy, also set:

- `NETVISOR_PUBLIC_HOSTNAME`
- `NETVISOR_TRUST_PROXY_HEADERS`
- `NETVISOR_FORWARDED_ALLOW_IPS`

## 2. Initialize the database

```powershell
mysql -u root -p < database\init.sql
```

## 3. Start the backend

```powershell
python run_server.py
```

Optional probe mode:

```powershell
python run_server.py --health-check
```

## 4. Start collection processes

```powershell
python run_agent.py
python run_gateway.py
```

Probe mode is available for both:

```powershell
python run_agent.py --health-check
python run_gateway.py --health-check
```

## 5. Open the console

Browse to the dashboard on the backend URL shown by `run_server.py`.

## 6. Build frontend and bundles

```powershell
cd frontend
npm run build
```

```powershell
cd ..
python scripts/build_deploy_bundles.py --role server --role agent --role gateway
```
