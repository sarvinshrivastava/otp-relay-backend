// Package config loads and validates all runtime configuration from the
// environment. It is the single source of truth for tunables — no other
// package should read os.Getenv directly.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

// Config holds every runtime setting the relay needs. It is built once at
// startup by Load and then passed (read-only) into the packages that need it.
type Config struct {
	// Port is the TCP port the HTTP/WS server listens on inside the container.
	// On the VPS the shared Nginx proxies an auto-assigned host port to this.
	Port string

	// DBPath is the SQLite file location (a Docker volume in production).
	DBPath string

	// TOTPSecret is the base32 shared secret backing the dashboard login.
	TOTPSecret string

	// VAPID keys + subject authenticate Web Push messages to browsers.
	VAPIDPublicKey  string
	VAPIDPrivateKey string
	VAPIDSubject    string

	// ClaimWindow is how long the relay waits for a *second* claimant before
	// delivering an OTP. A second claim inside this window invalidates both.
	ClaimWindow time.Duration

	// OTPTTL is how long an OTP stays claimable before it expires. Real OTPs
	// live 1–5 min, so this must never be set as aggressively as 30s.
	OTPTTL time.Duration

	// SessionSecret signs dashboard session cookies (HMAC).
	SessionSecret string

	// SessionDuration is how long a dashboard session cookie stays valid.
	SessionDuration time.Duration

	// CookieSecure controls the Secure flag on the session cookie. True in
	// production (TLS terminates at Nginx, browser sees HTTPS); set
	// RELAY_ENV=development to disable it for plain-HTTP local testing.
	CookieSecure bool
}

// Load reads .env (if present), pulls every variable, applies defaults, and
// fails fast on anything missing or malformed. Returning an error here — rather
// than discovering a bad config at request time — keeps misconfiguration loud.
func Load() (*Config, error) {
	// .env is optional: in production vps-deploy injects real env vars, so a
	// missing file is not an error. We only surface genuine parse failures.
	_ = godotenv.Load()

	cfg := &Config{
		Port:            getenv("RELAY_PORT", "8080"),
		DBPath:          getenv("DB_PATH", "/data/relay.db"),
		TOTPSecret:      os.Getenv("TOTP_SECRET"),
		VAPIDPublicKey:  os.Getenv("VAPID_PUBLIC_KEY"),
		VAPIDPrivateKey: os.Getenv("VAPID_PRIVATE_KEY"),
		VAPIDSubject:    getenv("VAPID_SUBJECT", "mailto:admin@sarvinshrivastava.space"),
		SessionSecret:   os.Getenv("SESSION_SECRET"),
		CookieSecure:    getenv("RELAY_ENV", "production") != "development",
	}

	claimMS, err := getenvInt("CLAIM_WINDOW_MS", 7000)
	if err != nil {
		return nil, err
	}
	cfg.ClaimWindow = time.Duration(claimMS) * time.Millisecond

	ttlMS, err := getenvInt("OTP_TTL_MS", 120000)
	if err != nil {
		return nil, err
	}
	cfg.OTPTTL = time.Duration(ttlMS) * time.Millisecond

	sessHours, err := getenvInt("SESSION_DURATION_HOURS", 24)
	if err != nil {
		return nil, err
	}
	cfg.SessionDuration = time.Duration(sessHours) * time.Hour

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// validate enforces that security-critical secrets are actually present. The
// relay's whole threat model rests on these — booting without them would create
// a silently insecure server, so we refuse to start instead.
func (c *Config) validate() error {
	var missing []string
	if c.TOTPSecret == "" {
		missing = append(missing, "TOTP_SECRET")
	}
	if c.SessionSecret == "" {
		missing = append(missing, "SESSION_SECRET")
	}
	if c.VAPIDPublicKey == "" {
		missing = append(missing, "VAPID_PUBLIC_KEY")
	}
	if c.VAPIDPrivateKey == "" {
		missing = append(missing, "VAPID_PRIVATE_KEY")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required config: %v (generate secrets with cmd/gen-totp-secret and cmd/gen-vapid)", missing)
	}
	if c.OTPTTL < 30*time.Second {
		return fmt.Errorf("OTP_TTL_MS too low (%s): real OTPs live 1-5 min, refusing to expire that fast", c.OTPTTL)
	}
	return nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) (int, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid %s=%q: must be an integer", key, raw)
	}
	return n, nil
}
