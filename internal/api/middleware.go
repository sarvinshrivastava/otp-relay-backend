package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/sarvinshrivastava/otp-relay-backend/internal/db"
	"github.com/sarvinshrivastava/otp-relay-backend/internal/registry"
)

// ctxKey is an unexported type for context keys, preventing collisions with
// keys set by other packages on the same request context.
type ctxKey int

const deviceCtxKey ctxKey = iota

// requestLogger logs method, path, status, and latency for every request. It
// wraps the ResponseWriter to capture the status code.
func (a *API) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		a.log.Info("api request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

// requireSession rejects requests without a valid dashboard session cookie.
func (a *API) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := a.auth.ValidateRequest(r); err != nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireDeviceToken authenticates a device by bearer token and stashes the
// resolved device on the request context. Accepts `Authorization: Bearer <t>`
// or a `?token=` query param (parity with the WS endpoint).
func (a *API) requireDeviceToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if token == "" {
			writeError(w, http.StatusUnauthorized, "missing device token")
			return
		}

		dev, err := a.reg.Authenticate(token)
		switch {
		case errors.Is(err, db.ErrNotFound):
			writeError(w, http.StatusUnauthorized, "unknown device token")
			return
		case errors.Is(err, registry.ErrRevoked):
			writeError(w, http.StatusForbidden, "device revoked")
			return
		case err != nil:
			a.log.Error("device auth error", "error", err)
			writeError(w, http.StatusInternalServerError, "auth error")
			return
		}

		ctx := context.WithValue(r.Context(), deviceCtxKey, dev)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// deviceFromContext retrieves the authenticated device set by requireDeviceToken.
func deviceFromContext(r *http.Request) *db.Device {
	dev, _ := r.Context().Value(deviceCtxKey).(*db.Device)
	return dev
}

// corsMiddleware reflects the request Origin and allows credentials. The PWA is
// served same-origin in production, so this is mostly a convenience for local
// dev where the Vite dev server runs on a different port.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// bearerToken extracts a token from an Authorization: Bearer header.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if strings.HasPrefix(h, prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// statusRecorder captures the response status for logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
