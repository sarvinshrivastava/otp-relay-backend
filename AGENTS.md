# CLAUDE.md — otp-relay-backend

The core backend of a self-hosted, end-to-end encrypted OTP relay. It receives
encrypted OTP payloads from an Android source client and relays them to PWA
destination clients over WebSocket + Web Push, never seeing plaintext.

> Personal project. Use the personal GitHub token. The companion repos `otp-pwa`
> (frontend) and `otp-android` (source client) live alongside this one — **do not
> edit them from here**.

## Run locally

```bash
cp .env.example .env
go run ./cmd/gen-totp-secret   # paste TOTP_SECRET into .env, enrol authenticator
go run ./cmd/gen-vapid         # paste VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY
# also set SESSION_SECRET (openssl rand -hex 32) and DB_PATH=./data/relay.db
RELAY_ENV=development go run .  # development => non-Secure cookie so http login works
```

Server boots on `RELAY_PORT` (default 8080). Health check: `GET /health`.

## Test

```bash
go test ./...          # claim logic (dual-claim invariant) is covered in internal/claim
CGO_ENABLED=1 go build -o relay .   # full build (CGO required for go-sqlite3)
go vet ./...
```

## Package map (`internal/`)

| Package    | Responsibility |
|------------|----------------|
| `config`   | Env loading + validation. Fails fast on missing secrets. Single source of tunables. |
| `db`       | SQLite connection, schema (idempotent migrations), all SQL. No business logic. |
| `id`       | Crypto-random opaque identifiers (device ids/tokens, OTP ids, invite tokens). |
| `registry` | Device lifecycle — register / authenticate (token→device) / list / revoke. |
| `totp`     | Dashboard auth: TOTP verify + signed (HMAC) session cookie issue/validate. |
| `push`     | VAPID Web Push. Sends only a *signal* (OTP id), never the payload. |
| `ws`       | WebSocket transport: `hub.go` (registry + send/pumps + message types), `handler.go` (upgrade + token auth). Pure transport, no business logic. |
| `claim`    | OTP coordinator: ingest + push fan-out + **dual-claim invalidation** + expiry janitor. The security heart. |
| `api`      | chi REST router, session/device-token middleware, auth/devices/onboard/otp handlers. |

`main.go` wires everything and breaks the hub↔claim dependency cycle via a
late-bound dispatcher. `cmd/` holds the two key-generation tools.

## Deploy model (Option B — important)

This repo ships **only the relay container**. The **shared VPS Nginx** terminates
TLS, proxies `/ws` + `/api` to the relay's auto-assigned host port, and serves the
`otp-pwa` static files. We do **not** run our own Nginx (would collide on 80/443).
`nginx/otp.conf` is the reference vhost; `docker-compose.yml` runs relay-only;
`.github/workflows/deploy.yml` uses `vps-deploy`.

## What NOT to touch

- **`db.schema` columns** — add new idempotent `CREATE`/`ALTER ... IF NOT EXISTS`
  statements for migrations; never rename/drop existing columns destructively
  (production data lives in the `relay-db` volume).
- **Claim invariants** (`internal/claim`): the relay must never decrypt; a second
  claimant inside `CLAIM_WINDOW_MS` invalidates the OTP for *both*; a same-device
  retry must not self-invalidate; OTPs must not expire faster than 30s. The tests
  in `claim_test.go` encode these — keep them green.
- **Push payloads** (`internal/push`): never put ciphertext/plaintext in a push;
  only the OTP id signal. The biometric gate happens on the device before claim.
