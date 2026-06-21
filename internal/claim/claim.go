// Package claim is the OTP coordinator: it ingests encrypted OTPs from source
// devices, fans out push *signals* to destinations, and arbitrates claims with
// the dual-claim invalidation rule.
//
// Dual-claim rule (the security heart of the relay): when a destination claims
// an OTP, the relay waits CLAIM_WINDOW for a *second* claimant. If a second
// device claims the same OTP inside that window, the OTP is invalidated and
// NEITHER device receives it — a defence against a thief racing the legitimate
// user. A single claim inside the window is delivered to that device alone.
package claim

import (
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/sarvinshrivastava/otp-relay-backend/internal/db"
	"github.com/sarvinshrivastava/otp-relay-backend/internal/id"
	"github.com/sarvinshrivastava/otp-relay-backend/internal/push"
	"github.com/sarvinshrivastava/otp-relay-backend/internal/registry"
	"github.com/sarvinshrivastava/otp-relay-backend/internal/ws"
)

// Sender delivers a WS envelope to a connected device. *ws.Hub satisfies it.
// Declaring it here (rather than importing the hub concretely) keeps the claim
// logic unit-testable with a fake sender.
type Sender interface {
	SendToDevice(deviceID string, e ws.Envelope) bool
}

// Manager coordinates OTP ingestion and claims. It is safe for concurrent use.
type Manager struct {
	db       *db.DB
	sender   Sender
	push     *push.Notifier
	registry *registry.Registry
	window   time.Duration
	ttl      time.Duration
	log      *slog.Logger

	mu      sync.Mutex
	pending map[string]*claimState // otpID -> in-flight claim window
}

// claimState tracks an open claim window for one OTP.
type claimState struct {
	claimants []string    // device ids that have claimed, in arrival order
	timer     *time.Timer // fires when the window closes with a sole claimant
}

// New builds an OTP coordinator.
func New(database *db.DB, sender Sender, notifier *push.Notifier, reg *registry.Registry,
	window, ttl time.Duration, log *slog.Logger) *Manager {
	return &Manager{
		db:       database,
		sender:   sender,
		push:     notifier,
		registry: reg,
		window:   window,
		ttl:      ttl,
		log:      log,
		pending:  make(map[string]*claimState),
	}
}

// Ingest stores a new encrypted OTP from a source device and fans out push
// signals to every active destination. It returns the new OTP id. The relay
// stores only ciphertext + iv — it cannot read the OTP.
func (m *Manager) Ingest(sourceID, ciphertext, iv string) (string, error) {
	now := db.NowMillis()
	o := db.OTP{
		ID:         id.ShortID(),
		Ciphertext: ciphertext,
		IV:         iv,
		SourceID:   sourceID,
		CreatedAt:  now,
		ExpiresAt:  now + m.ttl.Milliseconds(),
		Status:     "pending",
	}
	if err := m.db.InsertOTP(o); err != nil {
		return "", err
	}

	m.dispatchPush(o.ID)
	m.log.Info("otp ingested", "otp_id", o.ID, "source_id", sourceID)
	return o.ID, nil
}

// dispatchPush sends the "an OTP is waiting" signal to all destination devices.
// The signal contains only the OTP id — never the payload (see push package).
func (m *Manager) dispatchPush(otpID string) {
	targets, err := m.registry.PushTargets()
	if err != nil {
		m.log.Error("load push targets", "error", err)
		return
	}
	subs := make([]string, 0, len(targets))
	for _, t := range targets {
		if t.PushSub != nil {
			subs = append(subs, *t.PushSub)
		}
	}
	if len(subs) == 0 {
		m.log.Warn("no destination push subscriptions for otp", "otp_id", otpID)
		return
	}
	dead := m.push.Broadcast(subs, otpID, m.log)
	if len(dead) > 0 {
		m.log.Info("push subscriptions gone", "count", len(dead))
	}
}

// Claim arbitrates a claim from a destination device. It implements the state
// machine in the package doc: terminal states reject/notify immediately; a
// pending OTP opens or joins a claim window.
func (m *Manager) Claim(claimantID, otpID string) {
	o, err := m.db.GetOTP(otpID)
	if errors.Is(err, db.ErrNotFound) {
		m.reject(claimantID, otpID, "otp not found")
		return
	}
	if err != nil {
		m.log.Error("load otp for claim", "otp_id", otpID, "error", err)
		m.reject(claimantID, otpID, "internal error")
		return
	}

	// Expiry is checked against the wall clock as well as stored status, so a
	// not-yet-swept OTP still can't be claimed past its TTL.
	if o.Status == "expired" || (o.Status == "pending" && o.ExpiresAt <= db.NowMillis()) {
		m.reject(claimantID, otpID, "otp expired")
		return
	}

	switch o.Status {
	case "claimed":
		m.reject(claimantID, otpID, "otp already claimed")
		return
	case "invalidated":
		// A prior dual-claim killed it; tell this late claimant too.
		m.sendInvalidated(claimantID, otpID)
		return
	}

	// status == "pending": enter the claim-window state machine.
	m.mu.Lock()
	st, open := m.pending[otpID]
	if !open {
		// First claimant — open the window and arm the resolve timer.
		st = &claimState{claimants: []string{claimantID}}
		st.timer = time.AfterFunc(m.window, func() { m.resolve(otpID) })
		m.pending[otpID] = st
		m.mu.Unlock()
		m.log.Info("claim window opened", "otp_id", otpID, "claimant", claimantID)
		return
	}

	// Window already open. A repeat claim from the same device is a no-op (e.g.
	// the PWA retried) — it must not trigger self-invalidation.
	for _, c := range st.claimants {
		if c == claimantID {
			m.mu.Unlock()
			return
		}
	}

	// A genuine SECOND claimant inside the window: invalidate for everyone.
	st.claimants = append(st.claimants, claimantID)
	st.timer.Stop()
	claimants := st.claimants
	delete(m.pending, otpID)
	m.mu.Unlock()

	m.log.Warn("dual claim detected, invalidating", "otp_id", otpID, "claimants", claimants)
	m.invalidate(otpID, claimants)
}

// resolve runs when a claim window closes. With exactly one claimant it delivers
// the payload; otherwise (defensive) it invalidates.
func (m *Manager) resolve(otpID string) {
	m.mu.Lock()
	st, ok := m.pending[otpID]
	if !ok {
		m.mu.Unlock()
		return // already resolved inline by a second claim
	}
	delete(m.pending, otpID)
	claimants := st.claimants
	m.mu.Unlock()

	if len(claimants) != 1 {
		m.invalidate(otpID, claimants)
		return
	}
	winner := claimants[0]

	// Re-load to make the claim atomic w.r.t. expiry/state at delivery time.
	o, err := m.db.GetOTP(otpID)
	if err != nil {
		m.reject(winner, otpID, "internal error")
		return
	}
	if o.Status != "pending" || o.ExpiresAt <= db.NowMillis() {
		m.reject(winner, otpID, "otp expired")
		return
	}

	if err := m.db.SetOTPStatus(otpID, "claimed", &winner); err != nil {
		m.log.Error("mark otp claimed", "otp_id", otpID, "error", err)
		m.reject(winner, otpID, "internal error")
		return
	}

	delivered := m.sender.SendToDevice(winner, ws.Envelope{
		Type:       ws.TypeOTPPayload,
		OTPID:      otpID,
		Ciphertext: o.Ciphertext,
		IV:         o.IV,
	})
	m.log.Info("otp delivered", "otp_id", otpID, "claimant", winner, "delivered", delivered)
}

// invalidate marks an OTP invalidated and notifies all of its claimants.
func (m *Manager) invalidate(otpID string, claimants []string) {
	if err := m.db.SetOTPStatus(otpID, "invalidated", nil); err != nil {
		m.log.Error("mark otp invalidated", "otp_id", otpID, "error", err)
	}
	for _, c := range claimants {
		m.sendInvalidated(c, otpID)
	}
}

func (m *Manager) sendInvalidated(deviceID, otpID string) {
	m.sender.SendToDevice(deviceID, ws.Envelope{
		Type:   ws.TypeOTPInvalidated,
		OTPID:  otpID,
		Reason: "claimed by more than one device",
	})
}

func (m *Manager) reject(deviceID, otpID, reason string) {
	m.sender.SendToDevice(deviceID, ws.Envelope{
		Type:  ws.TypeError,
		OTPID: otpID,
		Error: reason,
	})
}

// StartJanitor launches a background goroutine that periodically sweeps expired
// OTPs to the 'expired' status. It stops when the returned stop func is called.
func (m *Manager) StartJanitor(interval time.Duration) (stop func()) {
	ticker := time.NewTicker(interval)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				n, err := m.db.ExpireStaleOTPs(db.NowMillis())
				if err != nil {
					m.log.Error("expire sweep", "error", err)
				} else if n > 0 {
					m.log.Info("expired stale otps", "count", n)
				}
			case <-done:
				ticker.Stop()
				return
			}
		}
	}()
	return func() { close(done) }
}
