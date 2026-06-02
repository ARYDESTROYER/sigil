package api

import "net/http"

// apiError is the typed JSON error envelope returned by every sigild endpoint
// that fails. `Error` is a short, stable, machine-readable code (e.g.
// "not_implemented"); `Detail` is a human-readable explanation. Optional
// context fields are omitted when empty.
//
// STATUS: pre-audit skeleton. The set of error codes is not yet frozen.
type apiError struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
	// VaultID is set on vault-scoped errors so callers can correlate the
	// response with the requested vault. Omitted when not applicable.
	VaultID string `json:"vaultID,omitempty"`
}

// writeError writes a typed JSON error envelope with the given status code.
func writeError(w http.ResponseWriter, status int, code, detail string) {
	writeJSON(w, status, apiError{Error: code, Detail: detail})
}
