// Package api exposes the relay's public REST surface under /api. The dashboard
// (served as static files by Nginx, same-origin) calls these endpoints; routes
// are split into session-gated (TOTP dashboard) and device-token-gated (Android
// source / PWA claim) groups.
package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/sarvinshrivastava/otp-relay-backend/internal/claim"
	"github.com/sarvinshrivastava/otp-relay-backend/internal/db"
	"github.com/sarvinshrivastava/otp-relay-backend/internal/registry"
	"github.com/sarvinshrivastava/otp-relay-backend/internal/totp"
)

// inviteTTL bounds how long an onboarding invite (and its QR) stays valid.
const inviteTTL = 15 * time.Minute

// API bundles the dependencies every handler shares.
type API struct {
	reg    *registry.Registry
	auth   *totp.Authenticator
	claims *claim.Manager
	db     *db.DB
	log    *slog.Logger
}

// New builds the API handler set.
func New(reg *registry.Registry, auth *totp.Authenticator, claims *claim.Manager,
	database *db.DB, log *slog.Logger) *API {
	return &API{reg: reg, auth: auth, claims: claims, db: database, log: log}
}

// Routes returns the chi router mounted at /api. The grouping below is the
// authorization model in code form:
//
//	/auth/login           public (you prove identity here)
//	/auth/logout          session
//	/devices, /onboard    session (dashboard operator only)
//	/otp/push, /otp/claim device token (Android + PWA)
func (a *API) Routes() http.Handler {
	r := chi.NewRouter()

	r.Use(a.requestLogger)
	r.Use(corsMiddleware)

	// --- public ---
	r.Post("/auth/login", a.handleLogin)

	// --- dashboard session-gated ---
	r.Group(func(r chi.Router) {
		r.Use(a.requireSession)

		r.Post("/auth/logout", a.handleLogout)

		r.Get("/devices", a.handleListDevices)
		r.Post("/devices", a.handleCreateDevice)
		r.Delete("/devices/{id}", a.handleDeleteDevice)

		r.Post("/onboard/invite", a.handleCreateInvite)
		r.Get("/onboard/qr", a.handleInviteQR)
	})

	// --- device-token-gated (source push + PWA claim) ---
	r.Group(func(r chi.Router) {
		r.Use(a.requireDeviceToken)

		r.Post("/otp/push", a.handleOTPPush)
		r.Post("/otp/claim", a.handleOTPClaim)
	})

	return r
}
