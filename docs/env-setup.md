# Environment Setup

NetVisor keeps a clean split between tracked templates and local secrets.

## Files

- `.env.example`
  - tracked in git
  - acts as the canonical list of required variables
  - contains placeholders only
- `.env`
  - local machine file
  - ignored by git
  - contains real values for one developer or one deployment target

## Why This Split Exists

- It keeps secrets out of the repository.
- It gives new contributors a safe bootstrap path.
- It keeps deployment bundles explicit, because each role gets its own local env template.

## Local Bootstrap

Create `.env` from the tracked template:

```powershell
python scripts/init_env.py
```

If you already have a local `.env` and want to regenerate it from the template:

```powershell
python scripts/init_env.py --force
```

## Deployment Bundles

- The server, agent, and gateway bundles each include a role-local `.env.example`.
- Those bundle templates are used for packaging, not for local development.
- The canonical root template still lives at the repository root.

## Guidance

- Never commit `.env`.
- Update `.env.example` when a new variable is added.
- Keep deployment-specific secrets in the deployment system or the generated `.env` for that target.
- If you need a lab-only LAN HTTP test between the backend and a copied agent or gateway, set `NETVISOR_ALLOW_LAN_HTTP=true` on both sides. Leave it `false` for normal use.
