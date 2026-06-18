package api

import (
	"errors"
	"net/http"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/sarvinshrivastava/otp-relay-backend/internal/db"
	"github.com/sarvinshrivastava/otp-relay-backend/internal/id"
)

type inviteResponse struct {
	Token     string `json:"token"`
	URL       string `json:"url"`
	ExpiresAt int64  `json:"expiresAt"`
}

// handleCreateInvite mints a single-use onboarding invite token (consumed when
// a device registers through it) and returns the deep-link URL a new device
// scans. The QR for this token is served by handleInviteQR.
func (a *API) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	now := db.NowMillis()
	tok := db.InviteToken{
		Token:     id.Token(),
		CreatedAt: now,
		ExpiresAt: now + inviteTTL.Milliseconds(),
		Used:      false,
	}
	if err := a.db.InsertInvite(tok); err != nil {
		a.log.Error("create invite", "error", err)
		writeError(w, http.StatusInternalServerError, "could not create invite")
		return
	}
	writeJSON(w, http.StatusCreated, inviteResponse{
		Token:     tok.Token,
		URL:       inviteURL(r, tok.Token),
		ExpiresAt: tok.ExpiresAt,
	})
}

// handleInviteQR renders the latest invite token as a PNG QR code. New devices
// scan it to obtain the onboarding deep link without typing the token by hand.
func (a *API) handleInviteQR(w http.ResponseWriter, r *http.Request) {
	tok, err := a.db.GetLatestInvite()
	if errors.Is(err, db.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no invite exists; create one first")
		return
	}
	if err != nil {
		a.log.Error("load latest invite", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load invite")
		return
	}

	png, err := qrcode.Encode(inviteURL(r, tok.Token), qrcode.Medium, 256)
	if err != nil {
		a.log.Error("encode qr", "error", err)
		writeError(w, http.StatusInternalServerError, "could not render qr")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store") // invite tokens are sensitive
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(png)
}

// inviteURL builds the onboarding deep link for an invite token. It derives the
// public origin from the request Host (the relay sits behind Nginx, which sets
// Host), defaulting to https since the relay is only ever served over TLS.
func inviteURL(r *http.Request, token string) string {
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "" && r.Host == "" {
		scheme = "http"
	}
	host := r.Host
	return scheme + "://" + host + "/onboard?invite=" + token
}
