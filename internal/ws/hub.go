// Package ws implements the WebSocket transport: a connection hub that tracks
// live devices by id, and the per-connection read/write pumps. Both the Android
// source client and PWA destination clients connect here.
package ws

import (
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Message type constants — the discriminator on every WS envelope.
const (
	TypeOTPPush        = "otp_push"        // Android -> relay: new encrypted OTP
	TypeOTPClaim       = "otp_claim"       // PWA -> relay: claim after biometric gate
	TypeOTPPayload     = "otp_payload"     // relay -> claiming PWA: ciphertext + iv
	TypeOTPInvalidated = "otp_invalidated" // relay -> claimants: dual-claim killed it
	TypeError          = "error"           // relay -> client: rejection reason
	TypePing           = "ping"            // keepalive
	TypePong           = "pong"            // keepalive
)

// Envelope is the single wire format for all WS messages. Fields are optional
// per type and omitted when empty, keeping payloads minimal.
type Envelope struct {
	Type       string `json:"type"`
	OTPID      string `json:"otpId,omitempty"`
	Ciphertext string `json:"ciphertext,omitempty"`
	IV         string `json:"iv,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Dispatcher receives inbound messages from clients. It is implemented outside
// this package (by main, bridging to the claim + storage logic) so ws stays a
// pure transport with no business logic and no dependency on claim.
type Dispatcher interface {
	// OnPush handles a new OTP from a source device.
	OnPush(sourceDeviceID string, e Envelope)
	// OnClaim handles a claim from a destination device (after its biometric gate).
	OnClaim(claimantDeviceID string, e Envelope)
}

// Timing constants for the keepalive / liveness machinery.
const (
	writeWait  = 10 * time.Second    // max time to write one frame
	pongWait   = 60 * time.Second    // max silence before we consider a peer dead
	pingPeriod = (pongWait * 9) / 10 // ping a bit more often than pongWait
	sendBuffer = 16                  // queued outbound frames per client
)

// Client is one live WebSocket connection bound to a device.
type Client struct {
	deviceID   string
	deviceType string // "source" | "destination"
	conn       *websocket.Conn
	send       chan []byte
	hub        *Hub
	log        *slog.Logger
}

// Hub is the registry of live clients, keyed by device id. A device may
// reconnect; the newest connection replaces the old one.
type Hub struct {
	mu         sync.RWMutex
	clients    map[string]*Client
	dispatcher Dispatcher
	log        *slog.Logger
}

// NewHub builds an empty hub.
func NewHub(dispatcher Dispatcher, log *slog.Logger) *Hub {
	return &Hub{
		clients:    make(map[string]*Client),
		dispatcher: dispatcher,
		log:        log,
	}
}

// register adds a client, displacing any prior connection for the same device.
func (h *Hub) register(c *Client) {
	h.mu.Lock()
	if old, ok := h.clients[c.deviceID]; ok {
		// A device opened a second connection — drop the stale one.
		close(old.send)
	}
	h.clients[c.deviceID] = c
	h.mu.Unlock()
	h.log.Info("ws client connected", "device_id", c.deviceID, "type", c.deviceType)
}

// unregister removes a client only if it is still the active one (guards against
// a displaced connection removing its replacement).
func (h *Hub) unregister(c *Client) {
	h.mu.Lock()
	if cur, ok := h.clients[c.deviceID]; ok && cur == c {
		delete(h.clients, c.deviceID)
		close(c.send)
	}
	h.mu.Unlock()
	h.log.Info("ws client disconnected", "device_id", c.deviceID)
}

// SendToDevice queues a JSON envelope to a device. Returns false if the device
// is not currently connected (or its buffer is full). This is the method the
// claim package depends on via its own Sender interface.
func (h *Hub) SendToDevice(deviceID string, e Envelope) bool {
	payload, err := json.Marshal(e)
	if err != nil {
		h.log.Error("marshal ws envelope", "error", err)
		return false
	}
	h.mu.RLock()
	c, ok := h.clients[deviceID]
	h.mu.RUnlock()
	if !ok {
		return false
	}
	select {
	case c.send <- payload:
		return true
	default:
		// Buffer full — peer is too slow. Drop rather than block the caller.
		h.log.Warn("ws send buffer full, dropping", "device_id", deviceID)
		return false
	}
}

// IsConnected reports whether a device has a live connection.
func (h *Hub) IsConnected(deviceID string) bool {
	h.mu.RLock()
	_, ok := h.clients[deviceID]
	h.mu.RUnlock()
	return ok
}

// readPump pumps inbound frames, dispatching each by type. It runs until the
// peer disconnects or violates the protocol/liveness rules.
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister(c)
		c.conn.Close()
	}()

	c.conn.SetReadLimit(64 * 1024) // ciphertext payloads are small; cap abuse
	_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(pongWait))
	})

	for {
		_, raw, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				c.log.Warn("ws read error", "device_id", c.deviceID, "error", err)
			}
			return
		}

		var e Envelope
		if err := json.Unmarshal(raw, &e); err != nil {
			c.sendError("malformed message")
			continue
		}
		c.handle(e)
	}
}

// handle routes one inbound envelope based on the sender's device type. Routing
// here enforces capability: only sources may push, only destinations may claim.
func (c *Client) handle(e Envelope) {
	switch e.Type {
	case TypePing:
		c.trySend(Envelope{Type: TypePong})
	case TypeOTPPush:
		if c.deviceType != "source" {
			c.sendError("only source devices may push")
			return
		}
		c.hub.dispatcher.OnPush(c.deviceID, e)
	case TypeOTPClaim:
		if c.deviceType != "destination" {
			c.sendError("only destination devices may claim")
			return
		}
		c.hub.dispatcher.OnClaim(c.deviceID, e)
	default:
		c.sendError("unknown message type: " + e.Type)
	}
}

// writePump pumps queued frames to the peer and sends periodic pings. A closed
// send channel (from unregister) ends the pump cleanly.
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case payload, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// Hub closed the channel — say goodbye.
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, payload); err != nil {
				return
			}
		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// trySend queues an envelope to this specific client, ignoring overflow.
func (c *Client) trySend(e Envelope) {
	payload, err := json.Marshal(e)
	if err != nil {
		return
	}
	select {
	case c.send <- payload:
	default:
	}
}

// sendError queues a typed error envelope to the client.
func (c *Client) sendError(reason string) {
	c.trySend(Envelope{Type: TypeError, Error: reason})
}
