// Package totp handles dashboard authentication: verifying a TOTP code against
// the shared secret, and issuing/validating signed session cookies. There is no
// user database — the dashboard is single-operator, gated entirely by TOTP.
package totp

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

// SessionCookieName is the cookie that carries the signed session.
const SessionCookieName = "otp_relay_session"

// ErrInvalidSession marks a missing, malformed, tampered, or expired session.
var ErrInvalidSession = errors.New("totp: invalid session")

// Authenticator verifies TOTP codes and mints/validates session cookies.
type Authenticator struct {
	secret       string        // base32 TOTP shared secret
	signingKey   []byte        // HMAC key for session cookies (SESSION_SECRET)
	sessionTTL   time.Duration // how long a freshly issued session lives
	cookieSecure bool          // Secure flag — true in prod (HTTPS via Nginx)
}

// New builds an Authenticator. cookieSecure should be true in production so the
// session cookie is only ever sent over HTTPS.
func New(totpSecret, sessionSecret string, sessionTTL time.Duration, cookieSecure bool) *Authenticator {
	return &Authenticator{
		secret:       totpSecret,
		signingKey:   []byte(sessionSecret),
		sessionTTL:   sessionTTL,
		cookieSecure: cookieSecure,
	}
}

// Verify checks a 6-digit TOTP code. A ±1 step skew is tolerated to absorb
// clock drift between the operator's authenticator app and the server.
func (a *Authenticator) Verify(code string) bool {
	code = strings.TrimSpace(code)
	return totp.Validate(code, a.secret)
}

// IssueCookie returns a signed session cookie valid for sessionTTL. The cookie
// value is "<expiryUnix>.<base64(hmac)>" — stateless, so no server-side session
// store is needed; validity is proven by the HMAC over the expiry.
func (a *Authenticator) IssueCookie() *http.Cookie {
	expiry := time.Now().Add(a.sessionTTL).Unix()
	value := a.sign(expiry)
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true, // not readable by JS — mitigates XSS session theft
		Secure:   a.cookieSecure,
		SameSite: http.SameSiteStrictMode, // dashboard is same-origin only
		Expires:  time.Unix(expiry, 0),
		MaxAge:   int(a.sessionTTL.Seconds()),
	}
}

// ClearCookie returns a cookie that immediately expires the session (logout).
func (a *Authenticator) ClearCookie() *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   a.cookieSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	}
}

// ValidateRequest extracts and verifies the session cookie on an incoming
// request. It returns ErrInvalidSession for anything that isn't a currently
// valid, untampered session.
func (a *Authenticator) ValidateRequest(r *http.Request) error {
	c, err := r.Cookie(SessionCookieName)
	if err != nil {
		return ErrInvalidSession
	}
	return a.validate(c.Value)
}

// sign produces "<expiry>.<base64(hmac(expiry))>".
func (a *Authenticator) sign(expiry int64) string {
	payload := strconv.FormatInt(expiry, 10)
	mac := a.hmac(payload)
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac)
}

// validate parses and verifies a cookie value, then checks expiry. HMAC is
// compared in constant time to avoid leaking signature bytes via timing.
func (a *Authenticator) validate(value string) error {
	idx := strings.LastIndexByte(value, '.')
	if idx <= 0 {
		return ErrInvalidSession
	}
	payload, sig := value[:idx], value[idx+1:]

	gotMAC, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return ErrInvalidSession
	}
	wantMAC := a.hmac(payload)
	if !hmac.Equal(gotMAC, wantMAC) {
		return ErrInvalidSession
	}

	expiry, err := strconv.ParseInt(payload, 10, 64)
	if err != nil {
		return ErrInvalidSession
	}
	if time.Now().Unix() > expiry {
		return ErrInvalidSession
	}
	return nil
}

func (a *Authenticator) hmac(payload string) []byte {
	h := hmac.New(sha256.New, a.signingKey)
	h.Write([]byte(payload))
	return h.Sum(nil)
}

// ConstantTimeEqualString compares two strings without early exit. Exposed for
// device-token comparison elsewhere, keeping all timing-safe compares in one
// reviewable spot.
func ConstantTimeEqualString(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
