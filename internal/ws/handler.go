package ws

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/gorilla/websocket"

	"github.com/sarvinshrivastava/otp-relay-backend/internal/db"
	"github.com/sarvinshrivastava/otp-relay-backend/internal/registry"
)

// authenticator is the slice of registry.Registry that the WS upgrade needs.
// Declaring it as a local interface keeps the handler testable and narrows the
// dependency to exactly "resolve a token to a device".
type authenticator interface {
	Authenticate(token string) (*db.Device, error)
}

// upgrader negotiates the HTTP->WS upgrade. CheckOrigin returns true because the
// real origin gate is the device_token: an attacker's page cannot forge a valid
// token, and the relay never relies on cookies for WS auth (so CSRF is moot).
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// Handler upgrades /ws requests, authenticating via the `token` query param.
type Handler struct {
	hub  *Hub
	auth authenticator
	log  *slog.Logger
}

// NewHandler builds the WS HTTP handler.
func NewHandler(hub *Hub, auth authenticator, log *slog.Logger) *Handler {
	return &Handler{hub: hub, auth: auth, log: log}
}

// ServeHTTP authenticates the device token, upgrades the connection, and starts
// the read/write pumps. Auth happens *before* the upgrade so we can reject with
// a clean HTTP status rather than opening then immediately closing a socket.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}

	dev, err := h.auth.Authenticate(token)
	switch {
	case errors.Is(err, db.ErrNotFound):
		http.Error(w, "unknown token", http.StatusUnauthorized)
		return
	case errors.Is(err, registry.ErrRevoked):
		http.Error(w, "device revoked", http.StatusForbidden)
		return
	case err != nil:
		h.log.Error("ws auth error", "error", err)
		http.Error(w, "auth error", http.StatusInternalServerError)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade already wrote an error response.
		h.log.Warn("ws upgrade failed", "error", err)
		return
	}

	client := &Client{
		deviceID:   dev.ID,
		deviceType: dev.Type,
		conn:       conn,
		send:       make(chan []byte, sendBuffer),
		hub:        h.hub,
		log:        h.log,
	}
	h.hub.register(client)

	// One goroutine each for reading and writing — the canonical gorilla layout.
	go client.writePump()
	go client.readPump()
}
