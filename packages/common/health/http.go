package health

import (
	"encoding/json"
	"net/http"
)

// Handler serves a checker over HTTP: 200 when healthy, 503 when not, with the
// report as JSON either way. The body is the point — a probe acts on the
// status code, a person reading it wants to know which dependency is down.
func Handler(checker *Checker) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		report := checker.Run(r.Context())

		w.Header().Set("Content-Type", "application/json")
		// No caching: a health answer is worthless the moment it is stale,
		// and something between here and the prober will cache it otherwise.
		w.Header().Set("Cache-Control", "no-store")
		if !report.Healthy {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(report)
	})
}
