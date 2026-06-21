// Package db owns the SQLite connection, schema, and every SQL statement in the
// relay. Keeping all queries here (rather than scattered through handlers) keeps
// the data layer auditable — a security-sensitive property for this project.
package db

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3" // CGO SQLite driver, registered as "sqlite3"
)

// ErrNotFound is returned by lookups when no matching row exists. Callers switch
// on this rather than sql.ErrNoRows so the driver stays an internal detail.
var ErrNotFound = errors.New("db: not found")

// schema is the full DDL, applied idempotently on every boot. Every statement
// is CREATE ... IF NOT EXISTS, so re-running it is a no-op — this is our
// lightweight "migration" strategy (see CLAUDE.md: do not edit existing columns
// destructively; add new migrations as additional idempotent statements).
const schema = `
CREATE TABLE IF NOT EXISTS devices (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    type         TEXT NOT NULL CHECK(type IN ('source', 'destination')),
    push_sub     TEXT,
    device_token TEXT NOT NULL UNIQUE,
    created_at   INTEGER NOT NULL,
    revoked      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS otps (
    id          TEXT PRIMARY KEY,
    ciphertext  TEXT NOT NULL,
    iv          TEXT NOT NULL,
    source_id   TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    claimed_by  TEXT,
    status      TEXT NOT NULL DEFAULT 'pending'
                CHECK(status IN ('pending', 'claimed', 'invalidated', 'expired'))
);

CREATE TABLE IF NOT EXISTS invite_tokens (
    token       TEXT PRIMARY KEY,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_devices_token ON devices(device_token);
CREATE INDEX IF NOT EXISTS idx_otps_status   ON otps(status);
`

// DB wraps the standard *sql.DB with the relay's typed query methods.
type DB struct {
	*sql.DB
}

// Device mirrors a row in the devices table. PushSub is nullable (sources have
// no push subscription), so it is a *string.
type Device struct {
	ID          string
	Name        string
	Type        string // "source" | "destination"
	PushSub     *string
	DeviceToken string
	CreatedAt   int64 // unix millis
	Revoked     bool
}

// OTP mirrors a row in the otps table. Ciphertext/IV are base64 — the relay
// never decrypts them, it only stores and forwards.
type OTP struct {
	ID         string
	Ciphertext string
	IV         string
	SourceID   string
	CreatedAt  int64
	ExpiresAt  int64
	ClaimedBy  *string
	Status     string
}

// InviteToken mirrors a row in the invite_tokens table.
type InviteToken struct {
	Token     string
	CreatedAt int64
	ExpiresAt int64
	Used      bool
}

// Open connects to the SQLite file and applies the schema. The connection
// string enables WAL mode and a busy timeout so the single writer (claim logic)
// doesn't trip "database is locked" under concurrent reads.
func Open(path string) (*DB, error) {
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on", path)
	sqlDB, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// SQLite is a single-file embedded DB; one writer at a time. Capping the
	// pool avoids spurious lock contention from idle connections.
	sqlDB.SetMaxOpenConns(1)

	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	if _, err := sqlDB.Exec(schema); err != nil {
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &DB{sqlDB}, nil
}

// NowMillis returns the current unix time in milliseconds — the single time
// unit used across the schema.
func NowMillis() int64 { return time.Now().UnixMilli() }

// ---- Devices -------------------------------------------------------------

// InsertDevice persists a newly registered device.
func (d *DB) InsertDevice(dev Device) error {
	_, err := d.Exec(
		`INSERT INTO devices (id, name, type, push_sub, device_token, created_at, revoked)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		dev.ID, dev.Name, dev.Type, dev.PushSub, dev.DeviceToken, dev.CreatedAt, boolToInt(dev.Revoked),
	)
	return err
}

// GetDeviceByToken resolves a device_token (used for WS + device-token auth).
// Revoked devices are returned too so callers can reject them with a clear
// reason; check dev.Revoked at the call site.
func (d *DB) GetDeviceByToken(token string) (*Device, error) {
	return d.scanDevice(d.QueryRow(
		`SELECT id, name, type, push_sub, device_token, created_at, revoked
		 FROM devices WHERE device_token = ?`, token))
}

// GetDeviceByID resolves a device by its public ID.
func (d *DB) GetDeviceByID(id string) (*Device, error) {
	return d.scanDevice(d.QueryRow(
		`SELECT id, name, type, push_sub, device_token, created_at, revoked
		 FROM devices WHERE id = ?`, id))
}

// ListDevices returns all devices (revoked included) newest first, for the
// dashboard.
func (d *DB) ListDevices() ([]Device, error) {
	rows, err := d.Query(
		`SELECT id, name, type, push_sub, device_token, created_at, revoked
		 FROM devices ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Device
	for rows.Next() {
		var dev Device
		var revoked int
		if err := rows.Scan(&dev.ID, &dev.Name, &dev.Type, &dev.PushSub,
			&dev.DeviceToken, &dev.CreatedAt, &revoked); err != nil {
			return nil, err
		}
		dev.Revoked = revoked != 0
		out = append(out, dev)
	}
	return out, rows.Err()
}

// ListPushTargets returns the push subscriptions of all active destination
// devices — the fan-out set for a new OTP notification.
func (d *DB) ListPushTargets() ([]Device, error) {
	rows, err := d.Query(
		`SELECT id, name, type, push_sub, device_token, created_at, revoked
		 FROM devices
		 WHERE type = 'destination' AND revoked = 0 AND push_sub IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Device
	for rows.Next() {
		var dev Device
		var revoked int
		if err := rows.Scan(&dev.ID, &dev.Name, &dev.Type, &dev.PushSub,
			&dev.DeviceToken, &dev.CreatedAt, &revoked); err != nil {
			return nil, err
		}
		dev.Revoked = revoked != 0
		out = append(out, dev)
	}
	return out, rows.Err()
}

// RevokeDevice marks a device revoked. Returns ErrNotFound if no such device.
func (d *DB) RevokeDevice(id string) error {
	res, err := d.Exec(`UPDATE devices SET revoked = 1 WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return affectedOrNotFound(res)
}

func (d *DB) scanDevice(row *sql.Row) (*Device, error) {
	var dev Device
	var revoked int
	err := row.Scan(&dev.ID, &dev.Name, &dev.Type, &dev.PushSub,
		&dev.DeviceToken, &dev.CreatedAt, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	dev.Revoked = revoked != 0
	return &dev, nil
}

// ---- OTPs ----------------------------------------------------------------

// InsertOTP stores an encrypted OTP payload pushed by a source device.
func (d *DB) InsertOTP(o OTP) error {
	_, err := d.Exec(
		`INSERT INTO otps (id, ciphertext, iv, source_id, created_at, expires_at, claimed_by, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		o.ID, o.Ciphertext, o.IV, o.SourceID, o.CreatedAt, o.ExpiresAt, o.ClaimedBy, o.Status,
	)
	return err
}

// GetOTP fetches a single OTP by id. Returns ErrNotFound if absent.
func (d *DB) GetOTP(id string) (*OTP, error) {
	var o OTP
	err := d.QueryRow(
		`SELECT id, ciphertext, iv, source_id, created_at, expires_at, claimed_by, status
		 FROM otps WHERE id = ?`, id).
		Scan(&o.ID, &o.Ciphertext, &o.IV, &o.SourceID, &o.CreatedAt, &o.ExpiresAt, &o.ClaimedBy, &o.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// SetOTPStatus transitions an OTP's status (and optionally its claimant). It is
// the only way claim logic mutates OTP state, keeping the state machine in one
// place.
func (d *DB) SetOTPStatus(id, status string, claimedBy *string) error {
	res, err := d.Exec(
		`UPDATE otps SET status = ?, claimed_by = ? WHERE id = ?`,
		status, claimedBy, id)
	if err != nil {
		return err
	}
	return affectedOrNotFound(res)
}

// ExpireStaleOTPs flips any pending OTP past its expiry to 'expired'. Run
// periodically by the janitor goroutine. Returns the number expired.
func (d *DB) ExpireStaleOTPs(nowMillis int64) (int64, error) {
	res, err := d.Exec(
		`UPDATE otps SET status = 'expired'
		 WHERE status = 'pending' AND expires_at <= ?`, nowMillis)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---- Invite tokens -------------------------------------------------------

// InsertInvite stores a freshly minted onboarding invite token.
func (d *DB) InsertInvite(t InviteToken) error {
	_, err := d.Exec(
		`INSERT INTO invite_tokens (token, created_at, expires_at, used) VALUES (?, ?, ?, ?)`,
		t.Token, t.CreatedAt, t.ExpiresAt, boolToInt(t.Used))
	return err
}

// GetInvite fetches an invite token by value. Returns ErrNotFound if absent.
func (d *DB) GetInvite(token string) (*InviteToken, error) {
	var t InviteToken
	var used int
	err := d.QueryRow(
		`SELECT token, created_at, expires_at, used FROM invite_tokens WHERE token = ?`, token).
		Scan(&t.Token, &t.CreatedAt, &t.ExpiresAt, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.Used = used != 0
	return &t, nil
}

// GetLatestInvite returns the most recently created invite — used by the QR
// endpoint to render the current invite. Returns ErrNotFound if none exist.
func (d *DB) GetLatestInvite() (*InviteToken, error) {
	var t InviteToken
	var used int
	err := d.QueryRow(
		`SELECT token, created_at, expires_at, used FROM invite_tokens
		 ORDER BY created_at DESC LIMIT 1`).
		Scan(&t.Token, &t.CreatedAt, &t.ExpiresAt, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.Used = used != 0
	return &t, nil
}

// MarkInviteUsed consumes an invite token so it cannot be reused.
func (d *DB) MarkInviteUsed(token string) error {
	res, err := d.Exec(`UPDATE invite_tokens SET used = 1 WHERE token = ?`, token)
	if err != nil {
		return err
	}
	return affectedOrNotFound(res)
}

// ---- helpers -------------------------------------------------------------

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func affectedOrNotFound(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
