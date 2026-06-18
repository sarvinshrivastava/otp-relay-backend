package api

import (
	"encoding/json"
	"net/http"
)

// writeJSON serialises v as JSON with the given status. Encoding errors are
// logged by the caller's context, not surfaced to the client.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError emits a uniform {"error": "..."} body so the dashboard can render
// failures consistently.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// decodeJSON reads and validates a JSON request body into dst. It rejects bodies
// that are missing, malformed, or contain unknown fields (a small hardening
// against typo'd or smuggled keys).
func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
