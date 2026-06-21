// Command gen-totp-secret generates a new TOTP secret for dashboard login and
// prints both the base32 secret (for TOTP_SECRET) and an otpauth:// URI you can
// paste into an authenticator app (Google Authenticator, Aegis, 1Password…).
//
//	go run ./cmd/gen-totp-secret
package main

import (
	"fmt"
	"os"

	"github.com/pquerna/otp/totp"
)

func main() {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "otp-relay",
		AccountName: "dashboard",
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate totp:", err)
		os.Exit(1)
	}

	fmt.Println("TOTP secret generated. Add this to your .env / secrets-manager:")
	fmt.Println()
	fmt.Printf("TOTP_SECRET=%s\n", key.Secret())
	fmt.Println()
	fmt.Println("Enrol an authenticator app with this URI (or render it as a QR):")
	fmt.Println(key.URL())
}
