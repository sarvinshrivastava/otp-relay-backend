package api

import "net/http"

type loginRequest struct {
	Code string `json:"code"` // 6-digit TOTP code from the operator's authenticator
}

// handleLogin verifies a TOTP code and, on success, sets the signed session
// cookie. This is the only public dashboard endpoint.
func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !a.auth.Verify(req.Code) {
		// Do not distinguish "wrong code" from "malformed" to a caller — both
		// are just "denied" from the client's perspective.
		writeError(w, http.StatusUnauthorized, "invalid code")
		return
	}
	http.SetCookie(w, a.auth.IssueCookie())
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleLogout clears the session cookie.
func (a *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, a.auth.ClearCookie())
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
