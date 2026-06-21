// Package registry is the device lifecycle layer. It wraps db with the business
// rules around registering, listing, resolving, and revoking devices, and owns
// generation of the opaque IDs/tokens that the rest of the system trusts.
package registry

import (
	"errors"
	"fmt"

	"github.com/sarvinshrivastava/otp-relay-backend/internal/db"
	"github.com/sarvinshrivastava/otp-relay-backend/internal/id"
)

// ErrRevoked is returned when a token resolves to a device that has been
// revoked — distinct from "unknown token" so the WS layer can log precisely.
var ErrRevoked = errors.New("registry: device revoked")

// ErrInvalidType guards the source/destination enum at the application layer
// (the DB CHECK constraint is the backstop).
var ErrInvalidType = errors.New("registry: type must be 'source' or 'destination'")

// Registry provides device operations on top of the database.
type Registry struct {
	db *db.DB
}

// New wires a Registry to the database.
func New(database *db.DB) *Registry {
	return &Registry{db: database}
}

// Register creates a device, minting a fresh ID and device_token. pushSub may be
// nil (sources never have one; destinations attach it later or at registration).
func (r *Registry) Register(name, typ string, pushSub *string) (*db.Device, error) {
	if typ != "source" && typ != "destination" {
		return nil, ErrInvalidType
	}
	dev := db.Device{
		ID:          id.ShortID(),
		Name:        name,
		Type:        typ,
		PushSub:     pushSub,
		DeviceToken: id.Token(),
		CreatedAt:   db.NowMillis(),
		Revoked:     false,
	}
	if err := r.db.InsertDevice(dev); err != nil {
		return nil, fmt.Errorf("register device: %w", err)
	}
	return &dev, nil
}

// Authenticate resolves a device_token to a live (non-revoked) device. This is
// the gate for every WS connection and device-token REST call. It returns
// db.ErrNotFound for unknown tokens and ErrRevoked for revoked ones.
func (r *Registry) Authenticate(token string) (*db.Device, error) {
	dev, err := r.db.GetDeviceByToken(token)
	if err != nil {
		return nil, err // db.ErrNotFound or a real error
	}
	if dev.Revoked {
		return nil, ErrRevoked
	}
	return dev, nil
}

// List returns all devices for the dashboard.
func (r *Registry) List() ([]db.Device, error) { return r.db.ListDevices() }

// PushTargets returns active destination devices that have a push subscription.
func (r *Registry) PushTargets() ([]db.Device, error) { return r.db.ListPushTargets() }

// Revoke marks a device revoked, immediately cutting off its token.
func (r *Registry) Revoke(id string) error { return r.db.RevokeDevice(id) }

// Get resolves a device by public ID.
func (r *Registry) Get(deviceID string) (*db.Device, error) { return r.db.GetDeviceByID(deviceID) }
