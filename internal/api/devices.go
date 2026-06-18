package api

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/sarvinshrivastava/otp-relay-backend/internal/db"
	"github.com/sarvinshrivastava/otp-relay-backend/internal/registry"
)

// deviceView is the dashboard-facing shape of a device. It deliberately OMITS
// device_token from the list view — tokens are secrets, returned only once at
// creation time (createDeviceResponse).
type deviceView struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	HasPush   bool   `json:"hasPush"`
	CreatedAt int64  `json:"createdAt"`
	Revoked   bool   `json:"revoked"`
}

func toView(d db.Device) deviceView {
	return deviceView{
		ID:        d.ID,
		Name:      d.Name,
		Type:      d.Type,
		HasPush:   d.PushSub != nil,
		CreatedAt: d.CreatedAt,
		Revoked:   d.Revoked,
	}
}

// handleListDevices returns every registered device (without tokens).
func (a *API) handleListDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := a.reg.List()
	if err != nil {
		a.log.Error("list devices", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list devices")
		return
	}
	views := make([]deviceView, 0, len(devices))
	for _, d := range devices {
		views = append(views, toView(d))
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": views})
}

type createDeviceRequest struct {
	Name    string  `json:"name"`
	Type    string  `json:"type"`              // "source" | "destination"
	PushSub *string `json:"pushSub,omitempty"` // optional Web Push subscription JSON
}

// createDeviceResponse returns the device token EXACTLY ONCE. The dashboard must
// surface it immediately (e.g. as a QR/copy field); it is never retrievable
// again, mirroring how API keys are handled.
type createDeviceResponse struct {
	deviceView
	DeviceToken string `json:"deviceToken"`
}

// handleCreateDevice registers a new device and returns its one-time token.
func (a *API) handleCreateDevice(w http.ResponseWriter, r *http.Request) {
	var req createDeviceRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	dev, err := a.reg.Register(req.Name, req.Type, req.PushSub)
	if errors.Is(err, registry.ErrInvalidType) {
		writeError(w, http.StatusBadRequest, "type must be 'source' or 'destination'")
		return
	}
	if err != nil {
		a.log.Error("register device", "error", err)
		writeError(w, http.StatusInternalServerError, "could not register device")
		return
	}

	writeJSON(w, http.StatusCreated, createDeviceResponse{
		deviceView:  toView(*dev),
		DeviceToken: dev.DeviceToken,
	})
}

// handleDeleteDevice revokes a device, immediately invalidating its token.
func (a *API) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "id")
	err := a.reg.Revoke(deviceID)
	if errors.Is(err, db.ErrNotFound) {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	if err != nil {
		a.log.Error("revoke device", "error", err)
		writeError(w, http.StatusInternalServerError, "could not revoke device")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
