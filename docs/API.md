# API reference

Base path: `/api` (proxied by the shared Nginx). WebSocket: `/ws`.

Auth legend: **None** · **Session** (dashboard TOTP cookie) · **Device** (device token).

## WebSocket — `/ws`

Connect with the device token as a query param:

```
wss://otp.vps.sarvinshrivastava.space/ws?token=<device_token>
```

Unknown token → `401`; revoked → `403`. After upgrade, all frames are JSON
envelopes with a `type` discriminator:

| `type`            | Direction        | Sender role | Fields |
|-------------------|------------------|-------------|--------|
| `otp_push`        | client → relay   | source      | `ciphertext`, `iv` |
| `otp_claim`       | client → relay   | destination | `otpId` |
| `otp_payload`     | relay → client   | —           | `otpId`, `ciphertext`, `iv` |
| `otp_invalidated` | relay → client   | —           | `otpId`, `reason` |
| `error`           | relay → client   | —           | `otpId?`, `error` |
| `ping` / `pong`   | both             | —           | — |

Capability is enforced by device type: only `source` devices may `otp_push`,
only `destination` devices may `otp_claim`. The claim *result* (`otp_payload`
or `otp_invalidated`) always arrives over the WS connection, after the claim
window resolves.

Example claim round-trip:

```jsonc
// PWA → relay (after passing biometric gate)
{"type":"otp_claim","otpId":"a1b2c3d4e5f6a7b8"}
// relay → PWA, ~CLAIM_WINDOW_MS later, sole claimant
{"type":"otp_payload","otpId":"a1b2c3d4e5f6a7b8","ciphertext":"…","iv":"…"}
```

## REST

### `POST /api/auth/login` — None
```jsonc
// req
{"code":"123456"}
// 200
{"ok":true}            // + Set-Cookie: otp_relay_session=…
// 401
{"error":"invalid code"}
```

### `POST /api/auth/logout` — Session
`200 {"ok":true}` and clears the cookie.

### `GET /api/devices` — Session
```jsonc
// 200 — note: device tokens are NOT included here
{"devices":[
  {"id":"…","name":"Pixel 8","type":"source","hasPush":false,"createdAt":1718700000000,"revoked":false}
]}
```

### `POST /api/devices` — Session
```jsonc
// req — pushSub is optional (destination devices attach a Web Push subscription)
{"name":"My Laptop","type":"destination","pushSub":"{…subscription JSON…}"}
// 201 — deviceToken returned EXACTLY ONCE; store it now
{"id":"…","name":"My Laptop","type":"destination","hasPush":true,
 "createdAt":1718700000000,"revoked":false,"deviceToken":"<64 hex chars>"}
```

### `DELETE /api/devices/{id}` — Session
`200 {"ok":true}` · `404 {"error":"device not found"}`. Revocation is immediate.

### `POST /api/onboard/invite` — Session
```jsonc
// 201 — single-use, expires in 15 min
{"token":"<64 hex>","url":"https://…/onboard?invite=<token>","expiresAt":1718700900000}
```

### `GET /api/onboard/qr` — Session
Returns `image/png` (256px QR) encoding the latest invite's onboarding URL.
`404` if no invite exists yet. `Cache-Control: no-store`.

### `POST /api/otp/push` — Device (source)
```jsonc
// req
{"ciphertext":"<base64>","iv":"<base64>"}
// 201
{"otpId":"a1b2c3d4e5f6a7b8"}
```

### `POST /api/otp/claim` — Device (destination)
```jsonc
// req
{"otpId":"a1b2c3d4e5f6a7b8"}
// 202 — result is delivered over the device's WebSocket connection
{"status":"claim registered; result delivered over websocket"}
```

### `GET /health` — None
`200 {"status":"ok"}` — liveness probe for vps-deploy / monitoring.

## Errors

All REST errors share the shape `{"error":"<message>"}`. Status codes follow
HTTP conventions: `400` bad body, `401` unauthenticated, `403` revoked / wrong
device type, `404` not found, `500` internal.
