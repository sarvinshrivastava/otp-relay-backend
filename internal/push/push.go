// Package push delivers Web Push notifications to destination devices via VAPID.
//
// SECURITY INVARIANT: the push payload carries only a *signal* — the OTP id and
// a "you have an OTP" prompt — never the ciphertext or plaintext. The PWA must
// pass a biometric/PIN gate and then fetch the payload over an authenticated
// channel. A push provider (or anyone who compromises one) therefore learns
// that an OTP exists, but never its contents.
package push

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	webpush "github.com/SherClockHolmes/webpush-go"
)

// Notifier dispatches Web Push messages signed with the relay's VAPID keys.
type Notifier struct {
	publicKey  string
	privateKey string
	subject    string
}

// New builds a Notifier from VAPID config.
func New(publicKey, privateKey, subject string) *Notifier {
	return &Notifier{publicKey: publicKey, privateKey: privateKey, subject: subject}
}

// Signal is the (intentionally minimal) JSON body delivered in a push. It tells
// the PWA an OTP is waiting and which id to claim — nothing sensitive.
type Signal struct {
	Type  string `json:"type"`  // always "otp_available"
	OTPID string `json:"otpId"` // id to claim after the biometric gate
}

// Notify sends a single push to one subscription. A 404/410 from the push
// service means the subscription is dead (browser unsubscribed); callers should
// treat that as a prune signal — Notify reports it via the returned Gone bool.
func (n *Notifier) Notify(rawSubscription, otpID string) (gone bool, err error) {
	var sub webpush.Subscription
	if err := json.Unmarshal([]byte(rawSubscription), &sub); err != nil {
		return false, fmt.Errorf("parse push subscription: %w", err)
	}

	body, err := json.Marshal(Signal{Type: "otp_available", OTPID: otpID})
	if err != nil {
		return false, fmt.Errorf("marshal signal: %w", err)
	}

	resp, err := webpush.SendNotification(body, &sub, &webpush.Options{
		Subscriber:      n.subject,
		VAPIDPublicKey:  n.publicKey,
		VAPIDPrivateKey: n.privateKey,
		TTL:             30, // seconds the push service holds it if device offline
		Urgency:         webpush.UrgencyHigh,
	})
	if err != nil {
		return false, fmt.Errorf("send push: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound, http.StatusGone:
		return true, nil // subscription is dead — caller should prune it
	}
	if resp.StatusCode >= 300 {
		return false, fmt.Errorf("push service returned %d", resp.StatusCode)
	}
	return false, nil
}

// Broadcast fans a signal out to many subscriptions concurrently, logging
// per-target failures rather than aborting the whole batch. It returns the list
// of subscriptions that came back Gone so the caller can prune them.
func (n *Notifier) Broadcast(subscriptions []string, otpID string, log *slog.Logger) (deadSubs []string) {
	type result struct {
		sub  string
		gone bool
	}
	results := make(chan result, len(subscriptions))

	for _, sub := range subscriptions {
		go func(sub string) {
			gone, err := n.Notify(sub, otpID)
			if err != nil {
				log.Warn("push delivery failed", "otp_id", otpID, "error", err)
			}
			results <- result{sub: sub, gone: gone}
		}(sub)
	}

	for range subscriptions {
		r := <-results
		if r.gone {
			deadSubs = append(deadSubs, r.sub)
		}
	}
	return deadSubs
}
