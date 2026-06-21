package api

import "net/http"

type otpPushRequest struct {
	Ciphertext string `json:"ciphertext"` // base64 AES-256-GCM ciphertext
	IV         string `json:"iv"`         // base64 IV
}

type otpPushResponse struct {
	OTPID string `json:"otpId"`
}

// handleOTPPush is the REST alternative to the WS otp_push message: a source
// device posts an encrypted OTP. Only source devices may push.
func (a *API) handleOTPPush(w http.ResponseWriter, r *http.Request) {
	dev := deviceFromContext(r)
	if dev.Type != "source" {
		writeError(w, http.StatusForbidden, "only source devices may push")
		return
	}

	var req otpPushRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Ciphertext == "" || req.IV == "" {
		writeError(w, http.StatusBadRequest, "ciphertext and iv are required")
		return
	}

	otpID, err := a.claims.Ingest(dev.ID, req.Ciphertext, req.IV)
	if err != nil {
		a.log.Error("ingest otp", "error", err)
		writeError(w, http.StatusInternalServerError, "could not store otp")
		return
	}
	writeJSON(w, http.StatusCreated, otpPushResponse{OTPID: otpID})
}

type otpClaimRequest struct {
	OTPID string `json:"otpId"`
}

// handleOTPClaim is the REST alternative to the WS otp_claim message: a
// destination device claims an OTP after passing its local biometric/PIN gate.
//
// The claim result (otp_payload or otp_invalidated) is delivered asynchronously
// over the device's WebSocket connection once the claim window resolves — the
// relay cannot return the payload synchronously without breaking the dual-claim
// window. Hence 202 Accepted: "claim registered, watch your WS channel".
func (a *API) handleOTPClaim(w http.ResponseWriter, r *http.Request) {
	dev := deviceFromContext(r)
	if dev.Type != "destination" {
		writeError(w, http.StatusForbidden, "only destination devices may claim")
		return
	}

	var req otpClaimRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.OTPID == "" {
		writeError(w, http.StatusBadRequest, "otpId is required")
		return
	}

	a.claims.Claim(dev.ID, req.OTPID)
	writeJSON(w, http.StatusAccepted, map[string]string{
		"status": "claim registered; result delivered over websocket",
	})
}
