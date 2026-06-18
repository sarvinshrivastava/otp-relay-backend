# Onboarding devices

There are two device roles:

- **source** — the Android phone that reads incoming OTPs and encrypts them.
- **destination** — a PWA (laptop/tablet) that receives the signal, gates on
  biometric/PIN, claims, and decrypts.

## 0. First-time server setup

```bash
go run ./cmd/gen-totp-secret   # TOTP_SECRET + an otpauth:// URI to enrol your authenticator
go run ./cmd/gen-vapid         # VAPID_PUBLIC_KEY (give to otp-pwa) + VAPID_PRIVATE_KEY
openssl rand -hex 32           # SESSION_SECRET
```

Put these in the VPS secrets-manager under the `OTP_RELAY_BACKEND_*` prefix (or
`.env` locally). Enrol the TOTP URI in your authenticator app — that code is how
you log into the dashboard.

## 1. Log into the dashboard

`POST /api/auth/login` with the current 6-digit TOTP code → session cookie. (The
otp-pwa dashboard UI does this for you.)

## 2. Register the Android source

```bash
curl -X POST https://otp.vps.sarvinshrivastava.space/api/devices \
  -H 'Content-Type: application/json' --cookie "otp_relay_session=…" \
  -d '{"name":"Pixel 8","type":"source"}'
```

The response contains `deviceToken` **once**. Enter it in the otp-android app
(or scan it). The app connects with `wss://…/ws?token=<deviceToken>` and shares
the AES key with destinations out-of-band (the relay is never told the key).

## 3. Register a destination PWA

The PWA first obtains a Web Push subscription from the browser (using
`VAPID_PUBLIC_KEY`), then registers:

```bash
curl -X POST https://otp.vps.sarvinshrivastava.space/api/devices \
  -H 'Content-Type: application/json' --cookie "otp_relay_session=…" \
  -d '{"name":"Work Laptop","type":"destination","pushSub":"<subscription JSON>"}'
```

Store the returned `deviceToken` in the PWA. It connects to `/ws?token=…` and
listens for `otp_available` push signals.

## 4. (Optional) QR-based onboarding

For hands-free enrolment of a new device:

1. `POST /api/onboard/invite` → mints a single-use, 15-min invite token + URL.
2. `GET /api/onboard/qr` → a PNG QR of that URL. Display it in the dashboard.
3. The new device scans the QR, opens the onboarding deep link
   (`/onboard?invite=<token>`), and the PWA completes registration against the
   invite. Invites are single-use and expire.

## 5. Revoking a device

```bash
curl -X DELETE https://otp.vps.sarvinshrivastava.space/api/devices/<id> \
  --cookie "otp_relay_session=…"
```

The device token stops working immediately (WS connections are rejected on the
next reconnect; in-flight ones drop on disconnect).

## Verifying the flow

1. Trigger an OTP on the source → it `otp_push`es ciphertext.
2. Every active destination gets a push signal (`otp_available`).
3. Open one destination, pass biometric → it claims → receives `otp_payload`,
   decrypts, shows the code.
4. To see dual-claim protection: claim the *same* OTP from two destinations
   within `CLAIM_WINDOW_MS` → both receive `otp_invalidated`, neither shows it.
