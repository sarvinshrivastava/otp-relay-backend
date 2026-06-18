# Security model

## Threat model

The relay is a **dumb, untrusted-by-design forwarder**. Assume the relay host,
its SQLite file, the network, and the browser push service may all be observed
by an adversary. The design ensures that even with all of that, an attacker
cannot read an OTP.

| Asset                | Protected by |
|----------------------|--------------|
| OTP plaintext        | AES-256-GCM, encrypted on the source device; relay only ever holds ciphertext + IV. |
| OTP at fetch time    | Per-fetch biometric/PIN gate on the destination device, before claim. |
| OTP under contention | Dual-claim invalidation within `CLAIM_WINDOW_MS`. |
| Dashboard            | TOTP login → HMAC-signed, HttpOnly, Secure, SameSite=Strict session cookie. |
| Device endpoints     | High-entropy (256-bit) device tokens; revocable. |

## Invariants (must always hold)

1. **No server-side decryption.** No code path turns ciphertext into plaintext.
   The relay has no decryption key and must never be given one.
2. **Push carries a signal only.** A Web Push body contains `{type, otpId}` —
   never ciphertext or plaintext. A compromised push service learns *that* an
   OTP exists, never its contents. (`internal/push`)
3. **Biometric gate precedes claim.** The relay delivers `otp_payload` only in
   response to a claim. The device is responsible for gating the claim behind
   biometric/PIN; the relay never embeds payload in the push notification.
4. **Dual-claim invalidation.** If two distinct devices claim one OTP within the
   window, the OTP is invalidated and delivered to neither — defeating a thief
   racing the legitimate user. A same-device retry is **not** a second claimant.
5. **Realistic expiry.** `OTP_TTL_MS` must be ≥ 30s (config refuses to boot
   otherwise); real OTPs live 1–5 min.

These are encoded as tests in `internal/claim/claim_test.go`. Changing claim
behaviour means updating those tests deliberately, not deleting them.

## Authentication

- **Dashboard (operator):** `POST /api/auth/login` verifies a 6-digit TOTP
  (±1 step skew tolerated) against `TOTP_SECRET`. Success issues a session
  cookie `value = "<expiryUnix>.<base64(HMAC-SHA256(expiry, SESSION_SECRET))>"`.
  Validation recomputes the HMAC and compares in constant time (`hmac.Equal`),
  then checks expiry. Stateless — no session store.
- **Devices (Android/PWA):** a 256-bit `device_token` minted at registration,
  passed as `?token=` on WS upgrade or `Authorization: Bearer` on REST. Resolved
  to a live, non-revoked device on every request. Revocation is immediate.

## Cookie flags

`HttpOnly` (no JS access → XSS can't steal it), `Secure` (HTTPS only; disabled
only when `RELAY_ENV=development` for local http), `SameSite=Strict` (the
dashboard is same-origin, so this removes CSRF as a concern).

## WebSocket origin

`CheckOrigin` returns true because WS auth rests entirely on the unguessable
`device_token`, not on cookies — so cross-site origins cannot forge a connection
and CSRF does not apply. A revoked or unknown token is rejected at upgrade.

## Hardening already in place

- JSON request bodies reject unknown fields (`DisallowUnknownFields`).
- WS read limit (64 KiB) + read/write deadlines + ping/pong liveness.
- `ReadHeaderTimeout` on the HTTP server (slowloris guard).
- Device tokens never returned by the list endpoint — only once at creation.
- `crypto/rand` for every identifier; the process panics rather than emit a
  guessable token if the RNG fails.
