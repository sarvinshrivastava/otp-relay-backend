# otp-relay-backend

A self-hosted, **end-to-end encrypted OTP relay**. An Android source client reads
an incoming OTP, encrypts it (AES-256-GCM) on-device, and pushes the ciphertext
to this relay. The relay fans out a Web Push *signal* to your PWA destination
devices; after you pass a biometric/PIN gate on a device, that device claims and
decrypts the OTP. **The relay never sees plaintext.**

```
┌─────────────┐  encrypted OTP   ┌─────────────┐  push signal   ┌─────────────┐
│ otp-android │ ───────────────▶ │  otp-relay  │ ─────────────▶ │   otp-pwa   │
│  (source)   │   /ws · /api     │  (this repo)│  (no payload)  │(destination)│
└─────────────┘                  └──────┬──────┘                └──────┬──────┘
                                        │   claim (after biometric)    │
                                        │ ◀────────────────────────────┘
                                        │   otp_payload (ciphertext+iv) over WS
                                        ▼
                                   SQLite (ciphertext only)
```

## Highlights

- **E2E encryption** — relay stores/forwards ciphertext + IV only; no server-side decryption.
- **Biometric-gated fetch** — push carries only a signal; payload is delivered after the device's local gate.
- **Dual-claim invalidation** — if two devices claim the same OTP within `CLAIM_WINDOW_MS` (default 7s), neither gets it.
- **Realistic expiry** — `OTP_TTL_MS` (default 2 min), never an artificial 30s.
- **Boring & auditable** — Go stdlib + chi, SQLite, no Redis/Postgres/ORM/JWT/OAuth.

## Quick start (local)

```bash
cp .env.example .env
go run ./cmd/gen-totp-secret    # -> TOTP_SECRET (+ enrol an authenticator app)
go run ./cmd/gen-vapid          # -> VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY
# set SESSION_SECRET=$(openssl rand -hex 32) and DB_PATH=./data/relay.db in .env
RELAY_ENV=development go run .
curl localhost:8080/health      # {"status":"ok"}
```

> CGO is required (the `go-sqlite3` driver compiles SQLite). macOS needs Xcode
> command-line tools; the Docker build installs `gcc musl-dev`.

## Tech stack

| Concern        | Library |
|----------------|---------|
| WebSocket      | `gorilla/websocket` |
| Web Push       | `SherClockHolmes/webpush-go` |
| SQLite         | `mattn/go-sqlite3` (CGO) |
| TOTP           | `pquerna/otp` |
| HTTP router    | `net/http` + `go-chi/chi/v5` |
| QR (onboarding)| `skip2/go-qrcode` |
| Env config     | `joho/godotenv` |
| Logging        | `log/slog` (stdlib) |

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — components, data flow, concurrency model
- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model & the invariants that defend it
- [`docs/API.md`](docs/API.md) — every REST + WebSocket endpoint
- [`docs/ONBOARDING.md`](docs/ONBOARDING.md) — registering source/destination devices
- [`CLAUDE.md`](CLAUDE.md) — contributor map & what-not-to-touch

## Deploy

Deploy model **Option B**: this repo ships only the relay container; the shared
VPS Nginx terminates TLS, proxies `/ws` + `/api`, and serves the `otp-pwa` dist.
Push to `main` → GitHub Actions → `vps-deploy`. See `nginx/otp.conf` for the
reference vhost and `docs/ARCHITECTURE.md` for the full picture.
