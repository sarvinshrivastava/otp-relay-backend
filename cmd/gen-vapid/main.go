// Command gen-vapid generates a VAPID key pair for Web Push. The private key
// goes in the relay's env (VAPID_PRIVATE_KEY); the public key is shared with the
// PWA so browsers can subscribe to push for this server.
//
//	go run ./cmd/gen-vapid
package main

import (
	"fmt"
	"os"

	webpush "github.com/SherClockHolmes/webpush-go"
)

func main() {
	privateKey, publicKey, err := webpush.GenerateVAPIDKeys()
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate vapid keys:", err)
		os.Exit(1)
	}

	fmt.Println("VAPID key pair generated.")
	fmt.Println()
	fmt.Println("Relay env (.env / secrets-manager):")
	fmt.Printf("VAPID_PUBLIC_KEY=%s\n", publicKey)
	fmt.Printf("VAPID_PRIVATE_KEY=%s\n", privateKey)
	fmt.Println()
	fmt.Println("Give the PUBLIC key to the otp-pwa frontend so browsers can subscribe.")
}
