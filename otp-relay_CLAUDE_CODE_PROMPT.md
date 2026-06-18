# Claude Code Handoff — `otp-relay`

> Read this entire file before writing any code. Use Plan Mode for initial breakdown.

---

## 1. What this repo is

The **core backend** of a self-hosted, end-to-end encrypted OTP relay system.

Receives encrypted OTP payloads from an Android source client, relays them to
destination PWA clients via WebSocket + Web Push, and handles all auth, device
management, and claim logic.

**This repo also owns:**
- Nginx config (`nginx/otp.conf`) for path-split routing
- `docker-compose.yml` wiring relay + Nginx together on the VPS

**Companion repos (separate, do not touch):**
- `otp-pwa` — Vite + React frontend (built dist served by Nginx)
- `otp-android` — Kotlin Android source client

---

## 2. Non-negotiable requirements

### Security model
- **End-to-end encryption.** AES-256-GCM. The relay never sees plaintext OTPs —
  only ciphertext + an opaque device ID. Do not add any server-side decryption.
- **Biometric / PIN gate on every fetch.** The relay dispatches a Web Push
  notification. The PWA only fetches the OTP payload *after* the user passes
  biometric/PIN on their device. The relay must not deliver payload in the
  push notification itself — only a signal.
- **Dual-claim invalidation.** If two devices both claim the same OTP within
  the claim window (`CLAIM_WINDOW_MS`, default 7000ms), neither gets it —
  the OTP is deleted and both receive an `invalidated` response.
  A single legitimate claim within the window delivers the payload to that device only.
- **Real OTP expiry is 1–5 minutes.** The relay must not expire OTPs in 30s.
  Use `OTP_TTL_MS` env var, default `120000` (2 min).

### Inter-repo boundaries
- The relay exposes a **public-facing REST API** at `/api` for the PWA dashboard.
  There is no separate internal port — dashboard calls go through the same
  server, gated by TOTP session middleware.
- Nginx proxies `/ws` and `/api` to the Go relay. Everything else (`/`, `/assets`)
  is served as static files from the built `otp-pwa` dist directory.

---

## 3. Tech stack

| Concern | Library |
|---|---|
| WebSocket | `github.com/gorilla/websocket` |
| Web Push (VAPID) | `github.com/SherClockHolmes/webpush-go` |
| SQLite | `github.com/mattn/go-sqlite3` (CGO) |
| TOTP | `github.com/pquerna/otp` |
| HTTP router | `net/http` + `github.com/go-chi/chi/v5` |
| Env config | `github.com/joho/godotenv` |
| Logging | `log/slog` (stdlib, Go 1.21+) |

Do not introduce: Redis, Postgres, ORMs, JWT, OAuth, gRPC, or any framework
beyond chi. Keep it boring and auditable.

---

## 4. Repo structure

```
otp-relay/
├── CLAUDE.md                  # Project-level Claude context (you write this)
├── README.md
├── .gitignore
├── .env.example
├── go.mod
├── go.sum
├── main.go                    # Entry point — wires everything, starts server
├── docker-compose.yml         # Wires relay + Nginx
├── Dockerfile                 # Multi-stage: golang:1.22-alpine build → alpine final
├── nginx/
│   └── otp.conf               # Nginx vhost config (see section 6)
├── internal/
│   ├── config/
│   │   └── config.go          # Env var loading + validation
│   ├── db/
│   │   └── db.go              # SQLite init, migrations, query helpers
│   ├── ws/
│   │   └── hub.go             # WebSocket hub — connection registry, broadcast
│   │   └── handler.go         # WebSocket HTTP upgrade handler
│   ├── push/
│   │   └── push.go            # VAPID Web Push dispatch
│   ├── claim/
│   │   └── claim.go           # Claim window logic + dual-claim invalidation
│   ├── totp/
│   │   └── totp.go            # TOTP verify, session cookie issue/validate
│   ├── registry/
│   │   └── registry.go        # Device CRUD (wraps db/)
│   └── api/
│       ├── router.go          # chi router, middleware wiring
│       ├── middleware.go      # TOTP session gate, CORS, request logging
│       ├── otp.go             # POST /api/otp/push, POST /api/otp/claim
│       ├── devices.go         # GET/POST/DELETE /api/devices
│       ├── onboard.go         # POST /api/onboard/invite, GET /api/onboard/qr
│       └── auth.go            # POST /api/auth/login, POST /api/auth/logout
└── docs/
    ├── ARCHITECTURE.md
    ├── SECURITY.md
    ├── API.md                 # All REST + WS endpoints documented here
    └── ONBOARDING.md
```

---

## 5. API surface

### WebSocket — `/ws`
- Android source client connects here (authenticated via `device_token` query param)
- PWA destination clients connect here (authenticated via `device_token`)
- Message types (defined as Go constants in `internal/ws/`):
  - `otp_push` — Android → relay → relay fans out Web Push to all destination devices
  - `otp_claim` — PWA → relay (after biometric gate passes)
  - `otp_payload` — relay → claiming PWA (ciphertext + IV)
  - `otp_invalidated` — relay → both claimants (dual-claim scenario)
  - `ping` / `pong` — keepalive

### REST — `/api`

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/auth/login` | None | Submit TOTP code, receive session cookie |
| POST | `/api/auth/logout` | Session | Clear session |
| GET | `/api/devices` | Session | List registered devices |
| POST | `/api/devices` | Session | Register new device |
| DELETE | `/api/devices/:id` | Session | Revoke device |
| POST | `/api/onboard/invite` | Session | Generate invite token (embedded in QR) |
| GET | `/api/onboard/qr` | Session | Returns QR PNG for latest invite token |
| POST | `/api/otp/push` | Device token | Android posts encrypted OTP here (alt to WS) |
| POST | `/api/otp/claim` | Device token | PWA claims OTP after biometric gate |

---

## 6. Nginx config (`nginx/otp.conf`)

```nginx
server {
    listen 443 ssl;
    server_name otp.vps.sarvinshrivastava.space;

    ssl_certificate     /etc/letsencrypt/live/sarvinshrivastava.space/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sarvinshrivastava.space/privkey.pem;

    # Go relay — WebSocket
    location /ws {
        proxy_pass http://relay:PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 3600s;
    }

    # Go relay — REST API + TOTP auth
    location /api {
        proxy_pass http://relay:PORT;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Static PWA/Dashboard files
    location / {
        root /var/www/otp-pwa;
        try_files $uri $uri/ /index.html;
    }
}

server {
    listen 80;
    server_name otp.vps.sarvinshrivastava.space;
    return 301 https://$host$request_uri;
}
```

> Replace `PORT` with the value of `RELAY_PORT` env var.
> `/var/www/otp-pwa` is mounted from the built `otp-pwa` dist — see docker-compose.

---

## 7. docker-compose.yml

```yaml
services:
  relay:
    build: .
    restart: unless-stopped
    env_file: .env
    volumes:
      - relay-db:/data
    networks:
      - internal

  nginx:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/otp.conf:/etc/nginx/conf.d/otp.conf:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro
      - otp-pwa-dist:/var/www/otp-pwa:ro   # built dist from otp-pwa CI
    depends_on:
      - relay
    networks:
      - internal

volumes:
  relay-db:
  otp-pwa-dist:

networks:
  internal:
```

---

## 8. Env vars (`.env.example`)

```env
# Server
RELAY_PORT=8080

# SQLite
DB_PATH=/data/relay.db

# TOTP (generate secret with: go run ./cmd/gen-totp-secret)
TOTP_SECRET=

# Web Push (VAPID)
VAPID_PUBLIC_KEY=
VAPID_PRIVATE_KEY=
VAPID_SUBJECT=mailto:you@sarvinshrivastava.space

# Claim window
CLAIM_WINDOW_MS=7000

# OTP TTL
OTP_TTL_MS=120000

# Session
SESSION_SECRET=
SESSION_DURATION_HOURS=24
```

---

## 9. Dockerfile (multi-stage)

```dockerfile
# Stage 1: build
FROM golang:1.22-alpine AS builder
RUN apk add --no-cache gcc musl-dev   # required for CGO (go-sqlite3)
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o relay .

# Stage 2: run
FROM alpine:3.19
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/relay .
EXPOSE 8080
CMD ["./relay"]
```

---

## 10. SQLite schema

```sql
CREATE TABLE IF NOT EXISTS devices (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    type        TEXT NOT NULL CHECK(type IN ('source', 'destination')),
    push_sub    TEXT,              -- Web Push subscription JSON (destination only)
    device_token TEXT NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS otps (
    id          TEXT PRIMARY KEY,
    ciphertext  TEXT NOT NULL,     -- base64 AES-256-GCM ciphertext
    iv          TEXT NOT NULL,     -- base64 IV
    source_id   TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    claimed_by  TEXT,
    status      TEXT NOT NULL DEFAULT 'pending'
                CHECK(status IN ('pending', 'claimed', 'invalidated', 'expired'))
);

CREATE TABLE IF NOT EXISTS invite_tokens (
    token       TEXT PRIMARY KEY,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0
);
```

---

## 11. Key behaviours to implement correctly

### Claim window logic (`internal/claim/claim.go`)
```
On otp_claim received from device D for OTP id X:
  1. Load OTP X from DB — if not found or expired → reject
  2. If status == 'claimed' → reject (already taken)
  3. If status == 'invalidated' → send otp_invalidated to D
  4. Record D as claimant with timestamp
  5. Wait CLAIM_WINDOW_MS for any second claimant
  6a. If no second claimant → mark claimed_by=D, status='claimed', send otp_payload to D
  6b. If second claimant E arrives within window →
        mark status='invalidated', send otp_invalidated to both D and E
```

### TOTP session
- On successful TOTP verify → issue a signed session cookie (`SESSION_SECRET`)
- All `/api/devices`, `/api/onboard` routes require valid session
- `/api/auth/login` and `/ws` (device token auth) are exempt

### Device token auth (for Android + PWA WS connections)
- `device_token` is a UUID generated at registration time, stored in DB
- Passed as query param on WS connect: `wss://otp.vps.sarvinshrivastava.space/ws?token=...`
- Relay validates token on upgrade, rejects unknown/revoked tokens

---

## 12. VPS deploy notes

- This repo follows the `vps-service-template` pattern on `sarvinshrivastava.space` VPS
- VPS: Ubuntu, `72.61.233.71`, domain `sarvinshrivastava.space`
- Wildcard SSL cert already provisioned at `/etc/letsencrypt/live/sarvinshrivastava.space/`
- Secrets managed via self-hosted `secrets-manager` service on the VPS
- CI/CD: GitHub Actions → SSH deploy → `docker compose up -d --build`
- The `otp-pwa-dist` volume is populated by the `otp-pwa` repo's CI pipeline
  (it SSH-copies built dist to VPS, mounts into this compose via the named volume)

---

## 13. CLAUDE.md (you write this)

Write a `CLAUDE.md` at repo root covering:
- Repo purpose (2 lines)
- How to run locally (`go run .`)
- How to run tests (`go test ./...`)
- Key files map (internal/ package responsibilities)
- What not to touch (schema migrations, claim logic invariants)
