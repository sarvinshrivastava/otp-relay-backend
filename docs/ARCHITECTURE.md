# Architecture

## Components

```
                         ┌──────────────────────── otp-relay-backend ────────────────────────┐
                         │                                                                    │
  otp-android  ──/ws──▶  │  ws.Handler ─▶ ws.Hub ─┬─▶ claim.Manager ─▶ db (SQLite)            │
   (source)    ──/api─▶  │  api.Router (device tok)│        │                                  │
                         │                         │        └─▶ push.Notifier ──▶ Web Push     │
  otp-pwa      ──/ws──▶  │  ws.Handler ─▶ ws.Hub ──┘                  │                         │
 (destination) ──/api─▶  │  api.Router (session/device tok)          ▼                         │
                         │                                    browser push service             │
  dashboard    ──/api─▶  │  api.Router (TOTP session) ─▶ registry ─▶ db                         │
                         └────────────────────────────────────────────────────────────────────┘
```

Every box maps to a package under `internal/` (see `CLAUDE.md` for the table).
The guiding principle: **transport (`ws`, `api`) holds no business logic; the
business rules live in `claim` and `registry`; `db` holds all SQL.**

## End-to-end OTP flow

1. **Ingest.** A source device sends `otp_push` (WS) or `POST /api/otp/push`
   with `{ciphertext, iv}`. `claim.Manager.Ingest` stores a `pending` OTP
   (`OTP_TTL_MS` from now) and asks `push.Notifier` to broadcast.
2. **Signal.** `push` sends each destination a Web Push body of just
   `{type:"otp_available", otpId}` — **no payload**. Dead subscriptions
   (404/410) are reported back for pruning.
3. **Gate.** The PWA wakes, prompts the user for biometric/PIN locally. Only
   after that does it act.
4. **Claim.** The PWA sends `otp_claim {otpId}` (WS) or `POST /api/otp/claim`.
   `claim.Manager.Claim` runs the state machine below.
5. **Deliver / invalidate.** On a sole claim, the relay marks the OTP `claimed`
   and sends `otp_payload {ciphertext, iv}` over that device's WS connection.
   The PWA decrypts locally. On a dual claim it sends `otp_invalidated` to both.

## Claim state machine (`internal/claim`)

```
Claim(D, X):
  load X
    ├─ not found / expired        ─▶ error to D
    ├─ status == claimed          ─▶ error to D
    ├─ status == invalidated      ─▶ otp_invalidated to D
    └─ status == pending:
         no open window  ─▶ open window, record D, arm timer(CLAIM_WINDOW)
         window open:
            D already in it ─▶ no-op (retry-safe)
            new device E    ─▶ stop timer, invalidate X, otp_invalidated to {D,E}

timer fires (sole claimant D):
   re-check pending & not expired ─▶ mark claimed_by=D ─▶ otp_payload to D
```

The window is held **in memory** (`map[otpID]*claimState` guarded by a mutex);
the OTP's authoritative status lives in SQLite. Re-loading the row inside
`resolve` makes delivery atomic with respect to expiry.

## Concurrency model

- **One goroutine per WS connection** for reads, one for writes (gorilla
  pattern), plus a buffered `send` channel per client (overflow = drop, never
  block the hub).
- **Hub** is a `sync.RWMutex`-guarded `map[deviceID]*Client`; a reconnect
  displaces the stale connection.
- **Claim windows** use `time.AfterFunc`; the manager mutex guards the pending
  map only — DB writes happen outside the lock.
- **Janitor** goroutine sweeps `pending` OTPs past expiry to `expired` every
  30s (a safety net; claims also check the wall clock directly).
- **SQLite** runs in WAL mode with `MaxOpenConns(1)` — the single writer avoids
  lock contention; reads are fast and consistent.

## Why these boundaries

The hub and claim manager are mutually dependent (hub dispatches *inbound*
messages to claim; claim sends *outbound* messages via the hub). Rather than
merge them, each side depends on a **narrow interface** the other satisfies
(`ws.Dispatcher`, `claim.Sender`), and `main.go` wires them with a late-bound
dispatcher. This keeps `ws` a pure transport with zero knowledge of claims.
