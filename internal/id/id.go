// Package id generates opaque, high-entropy identifiers used as device ids,
// device tokens, OTP ids, and invite tokens. Centralising this means every
// trust-bearing identifier in the system is minted the same audited way.
package id

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// New returns nBytes of cryptographic randomness, hex-encoded (so the string is
// 2*nBytes chars). It panics if the OS RNG fails: a process that cannot produce
// randomness must not keep issuing guessable identifiers.
func New(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("id: crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b)
}

// ShortID is a 16-char public identifier (8 bytes) — for device and OTP ids.
func ShortID() string { return New(8) }

// Token is a 64-char secret bearer token (32 bytes / 256 bits) — for device
// tokens and invite tokens, which are credentials and must resist guessing.
func Token() string { return New(32) }
