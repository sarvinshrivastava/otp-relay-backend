// Command relay is the otp-relay server entry point. It wires every internal
// package together and serves /ws (WebSocket) and /api (REST) over a single
// HTTP listener; in production the shared VPS Nginx proxies these paths to it.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sarvinshrivastava/otp-relay-backend/internal/api"
	"github.com/sarvinshrivastava/otp-relay-backend/internal/claim"
	"github.com/sarvinshrivastava/otp-relay-backend/internal/config"
	"github.com/sarvinshrivastava/otp-relay-backend/internal/db"
	"github.com/sarvinshrivastava/otp-relay-backend/internal/push"
	"github.com/sarvinshrivastava/otp-relay-backend/internal/registry"
	"github.com/sarvinshrivastava/otp-relay-backend/internal/totp"
	"github.com/sarvinshrivastava/otp-relay-backend/internal/ws"
)

// expirySweepInterval is how often the janitor flips stale OTPs to 'expired'.
const expirySweepInterval = 30 * time.Second

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := run(logger); err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}
}

// run holds the real startup logic so every failure path returns an error
// (rather than calling os.Exit deep in the call stack), which keeps shutdown
// and testing clean.
func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer database.Close()
	logger.Info("database ready", "path", cfg.DBPath)

	// --- construct packages ---
	reg := registry.New(database)
	authn := totp.New(cfg.TOTPSecret, cfg.SessionSecret, cfg.SessionDuration, cfg.CookieSecure)
	notifier := push.New(cfg.VAPIDPublicKey, cfg.VAPIDPrivateKey, cfg.VAPIDSubject)

	// The hub and the claim manager are mutually dependent (the hub dispatches
	// inbound messages to claim; claim sends outbound messages via the hub). We
	// break the cycle with a dispatcher whose claim pointer is set after both
	// exist.
	dispatcher := &wsDispatcher{log: logger}
	hub := ws.NewHub(dispatcher, logger)
	claimMgr := claim.New(database, hub, notifier, reg, cfg.ClaimWindow, cfg.OTPTTL, logger)
	dispatcher.claims = claimMgr

	stopJanitor := claimMgr.StartJanitor(expirySweepInterval)
	defer stopJanitor()

	wsHandler := ws.NewHandler(hub, reg, logger)
	apiHandler := api.New(reg, authn, claimMgr, database, logger)

	// --- HTTP routing ---
	mux := http.NewServeMux()
	mux.Handle("/ws", wsHandler)
	mux.Handle("/api/", http.StripPrefix("/api", apiHandler.Routes()))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second, // slowloris guard on the header read
	}

	// --- run with graceful shutdown ---
	serverErr := make(chan error, 1)
	go func() {
		logger.Info("relay listening", "port", cfg.Port, "claim_window", cfg.ClaimWindow, "otp_ttl", cfg.OTPTTL)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		return err
	case sig := <-stop:
		logger.Info("shutdown signal received", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}

// wsDispatcher bridges inbound WebSocket messages to the claim coordinator. It
// implements ws.Dispatcher. claims is set during wiring (see run).
type wsDispatcher struct {
	claims *claim.Manager
	log    *slog.Logger
}

// OnPush handles an otp_push from a source device.
func (d *wsDispatcher) OnPush(sourceDeviceID string, e ws.Envelope) {
	if e.Ciphertext == "" || e.IV == "" {
		d.log.Warn("otp_push missing ciphertext/iv", "source_id", sourceDeviceID)
		return
	}
	if _, err := d.claims.Ingest(sourceDeviceID, e.Ciphertext, e.IV); err != nil {
		d.log.Error("ws ingest otp", "source_id", sourceDeviceID, "error", err)
	}
}

// OnClaim handles an otp_claim from a destination device.
func (d *wsDispatcher) OnClaim(claimantDeviceID string, e ws.Envelope) {
	if e.OTPID == "" {
		d.log.Warn("otp_claim missing otpId", "claimant", claimantDeviceID)
		return
	}
	d.claims.Claim(claimantDeviceID, e.OTPID)
}
