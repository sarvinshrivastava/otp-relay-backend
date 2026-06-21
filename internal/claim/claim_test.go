package claim

import (
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sarvinshrivastava/otp-relay-backend/internal/db"
	"github.com/sarvinshrivastava/otp-relay-backend/internal/ws"
)

// fakeSender records every envelope sent to each device so tests can assert on
// what claimants received.
type fakeSender struct {
	mu   sync.Mutex
	msgs map[string][]ws.Envelope
}

func newFakeSender() *fakeSender { return &fakeSender{msgs: map[string][]ws.Envelope{}} }

func (f *fakeSender) SendToDevice(deviceID string, e ws.Envelope) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs[deviceID] = append(f.msgs[deviceID], e)
	return true
}

func (f *fakeSender) last(deviceID string) (ws.Envelope, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.msgs[deviceID]
	if len(m) == 0 {
		return ws.Envelope{}, false
	}
	return m[len(m)-1], true
}

// newTestManager builds a Manager backed by a temp SQLite DB and a fake sender.
// notifier/registry are nil because the claim path under test never touches
// them (only Ingest does).
func newTestManager(t *testing.T, window time.Duration) (*Manager, *db.DB, *fakeSender) {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	sender := newFakeSender()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := New(database, sender, nil, nil, window, 2*time.Minute, log)
	return m, database, sender
}

func seedOTP(t *testing.T, database *db.DB, id string, ttl time.Duration) {
	t.Helper()
	now := db.NowMillis()
	o := db.OTP{
		ID: id, Ciphertext: "ct", IV: "iv", SourceID: "src",
		CreatedAt: now, ExpiresAt: now + ttl.Milliseconds(), Status: "pending",
	}
	if err := database.InsertOTP(o); err != nil {
		t.Fatalf("seed otp: %v", err)
	}
}

// A lone claim inside the window is delivered to that device after the window.
func TestSingleClaimDelivers(t *testing.T) {
	m, database, sender := newTestManager(t, 40*time.Millisecond)
	seedOTP(t, database, "otp1", time.Minute)

	m.Claim("deviceA", "otp1")

	// Before the window closes, nothing is delivered.
	if _, ok := sender.last("deviceA"); ok {
		t.Fatal("payload delivered before window closed")
	}

	time.Sleep(80 * time.Millisecond)

	got, ok := sender.last("deviceA")
	if !ok || got.Type != ws.TypeOTPPayload {
		t.Fatalf("expected otp_payload, got %+v (ok=%v)", got, ok)
	}
	if got.Ciphertext != "ct" || got.IV != "iv" {
		t.Fatalf("payload missing ciphertext/iv: %+v", got)
	}

	o, _ := database.GetOTP("otp1")
	if o.Status != "claimed" || o.ClaimedBy == nil || *o.ClaimedBy != "deviceA" {
		t.Fatalf("otp not marked claimed by deviceA: %+v", o)
	}
}

// Two distinct devices claiming inside the window invalidates the OTP for both.
func TestDualClaimInvalidates(t *testing.T) {
	m, database, sender := newTestManager(t, 200*time.Millisecond)
	seedOTP(t, database, "otp2", time.Minute)

	m.Claim("deviceA", "otp2")
	m.Claim("deviceB", "otp2") // second claimant inside the window

	for _, dev := range []string{"deviceA", "deviceB"} {
		got, ok := sender.last(dev)
		if !ok || got.Type != ws.TypeOTPInvalidated {
			t.Fatalf("%s expected otp_invalidated, got %+v (ok=%v)", dev, got, ok)
		}
	}

	o, _ := database.GetOTP("otp2")
	if o.Status != "invalidated" {
		t.Fatalf("otp not invalidated: %+v", o)
	}
}

// A repeat claim from the SAME device must not self-invalidate.
func TestRepeatClaimSameDeviceDelivers(t *testing.T) {
	m, database, sender := newTestManager(t, 40*time.Millisecond)
	seedOTP(t, database, "otp3", time.Minute)

	m.Claim("deviceA", "otp3")
	m.Claim("deviceA", "otp3") // retry, not a second device

	time.Sleep(80 * time.Millisecond)

	got, _ := sender.last("deviceA")
	if got.Type != ws.TypeOTPPayload {
		t.Fatalf("expected payload after same-device retry, got %+v", got)
	}
}

// Claiming an expired OTP is rejected with an error, never delivered.
func TestClaimExpiredRejected(t *testing.T) {
	m, database, sender := newTestManager(t, 40*time.Millisecond)
	seedOTP(t, database, "otp4", -time.Second) // already expired

	m.Claim("deviceA", "otp4")

	got, ok := sender.last("deviceA")
	if !ok || got.Type != ws.TypeError {
		t.Fatalf("expected error for expired otp, got %+v (ok=%v)", got, ok)
	}
}

// Claiming an already-claimed OTP is rejected.
func TestClaimAlreadyClaimedRejected(t *testing.T) {
	m, database, sender := newTestManager(t, 40*time.Millisecond)
	seedOTP(t, database, "otp5", time.Minute)
	claimed := "someoneElse"
	if err := database.SetOTPStatus("otp5", "claimed", &claimed); err != nil {
		t.Fatalf("preset claimed: %v", err)
	}

	m.Claim("deviceA", "otp5")

	got, ok := sender.last("deviceA")
	if !ok || got.Type != ws.TypeError {
		t.Fatalf("expected error for already-claimed otp, got %+v (ok=%v)", got, ok)
	}
}
