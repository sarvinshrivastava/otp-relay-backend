# VPS Service Template

A GitHub Template Repository for deploying Node.js services to the VPS at `*.vps.sarvinshrivastava.space`.

## Using this template

1. Click **"Use this template"** on GitHub and name your new repo (e.g. `notion-cache`)
2. Add a single GitHub secret to your new repo:
   - `SM_READ_TOKEN` — the read token for the secrets-manager
3. Add your service's secrets to secrets-manager under the `SERVICENAME_*` prefix (see convention below)
4. Push to `main` — the workflow auto-deploys your service

The VPS deploy script handles everything else: port assignment, Nginx vhost creation, and SSL via the wildcard cert at `*.vps.sarvinshrivastava.space`.

## Secret naming convention

Secrets in secrets-manager are namespaced by service name. The prefix is derived by uppercasing the repo name and replacing hyphens with underscores:

| Repo / service name | Secrets prefix    | Example secret          |
|---------------------|-------------------|-------------------------|
| `notion-cache`      | `NOTION_CACHE_`   | `NOTION_CACHE_API_KEY`  |
| `webhook-relay`     | `WEBHOOK_RELAY_`  | `WEBHOOK_RELAY_SECRET`  |
| `my-api`            | `MY_API_`         | `MY_API_DATABASE_URL`   |

At deploy time, `vps-deploy` fetches all secrets matching your service's prefix, strips the prefix, and writes them to `.env` inside the container.

## Adding secrets to secrets-manager

```bash
curl -X POST https://secrets.vps.sarvinshrivastava.space/api/secrets \
  -H "X-API-Key: <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"key":"NOTION_CACHE_API_KEY","value":"your-value","folder":"Root"}'
```

## What gets deployed

- Your service runs inside a Docker container built from the `Dockerfile`
- It is assigned a unique port automatically (starting at 3001, tracked in `/etc/vps-registry/ports.json`)
- An Nginx vhost is created at `<service-name>.vps.sarvinshrivastava.space` with HTTPS
- The container restarts automatically (`unless-stopped`)

## Local development

```bash
cp .env.example .env
# fill in .env values
npm install
npm run dev
```

## Project structure

```
├── .github/workflows/deploy.yml  # CI/CD — only needs SM_READ_TOKEN secret
├── src/index.js                   # Entry point — replace with your code
├── Dockerfile
├── docker-compose.yml
├── package.json
└── .env.example
```
