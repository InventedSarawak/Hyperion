// Package sse is an INBOUND adapter: it serves cortex's live finding feed to
// HTTP clients as Server-Sent Events.
//
// SSE rather than WebSockets or GraphQL subscriptions: the feed is one-way and
// text, which is exactly what SSE is for, and it survives proxies and needs no
// handshake or subscription protocol. It also keeps the gateway in the path —
// a client that streamed straight from cortex would bypass the authentication,
// rate limiting and metering that land here in v4.
package sse

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/ports"
)

// heartbeat keeps the connection alive through anything that closes idle
// sockets. A quiet feed is normal — findings arrive in bursts when a poll
// lands, and nothing at all in between.
const heartbeat = 20 * time.Second

// Handler streams findings to HTTP clients.
type Handler struct {
	client ports.FindingStreamClient
	log    *slog.Logger
}

// NewHandler wires the adapter to the intelligence client.
func NewHandler(client ports.FindingStreamClient, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{client: client, log: log}
}

// finding is the JSON one event carries. It is deliberately small: a feed is
// for noticing that something arrived, and the client asks for the full record
// when someone wants to read it.
type finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Kind        string   `json:"kind"`
	Severity    string   `json:"severity"`
	Score       float64  `json:"score"`
	Sources     []string `json:"sources"`
	PublishedAt string   `json:"publishedAt,omitempty"`
}

// ServeHTTP streams until the client disconnects or cortex ends the feed.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	kinds := parseKinds(r.URL.Query()["kind"])

	updates, err := h.client.StreamFindings(r.Context(), kinds)
	if err != nil {
		http.Error(w, "live feed unavailable", http.StatusServiceUnavailable)
		h.log.Warn("could not open the live feed", "error", err)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Proxies that buffer would defeat the point of a live feed.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ticker := time.NewTicker(heartbeat)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return

		case <-ticker.C:
			// A comment line: valid SSE, ignored by clients, enough to keep
			// the connection from being reaped as idle.
			if _, err := fmt.Fprint(w, ": keep-alive\n\n"); err != nil {
				return
			}
			flusher.Flush()

		case v, ok := <-updates:
			if !ok {
				// cortex ended the feed. Say so rather than holding a
				// connection open that will never carry anything again.
				_, _ = fmt.Fprint(w, "event: end\ndata: {}\n\n")
				flusher.Flush()
				return
			}

			payload, err := json.Marshal(toFinding(v))
			if err != nil {
				h.log.Warn("could not encode a finding for the live feed", "id", v.CVEID, "error", err)
				continue
			}
			if _, err := fmt.Fprintf(w, "event: finding\ndata: %s\n\n", payload); err != nil {
				return // the viewer went away mid-write
			}
			flusher.Flush()
		}
	}
}

// toFinding flattens a finding to what a feed row shows.
func toFinding(v model.Vulnerability) finding {
	out := finding{
		ID:          v.CVEID,
		Title:       v.Title,
		Description: v.Description,
		Kind:        string(v.Kind),
		Sources:     v.Sources,
	}
	if !v.PublishedAt.IsZero() {
		out.PublishedAt = v.PublishedAt.UTC().Format(time.RFC3339)
	}
	// The highest score is the one a reader cares about when several feeds
	// have scored the same finding differently.
	for _, s := range v.Scores {
		if s.BaseScore >= out.Score {
			out.Score, out.Severity = s.BaseScore, string(s.Severity)
		}
	}
	return out
}

// parseKinds reads ?kind=vulnerability&kind=malware. Anything unrecognised is
// ignored rather than rejected: an unknown filter should narrow nothing, not
// fail the request.
func parseKinds(values []string) []model.FindingKind {
	var out []model.FindingKind
	for _, v := range values {
		switch v {
		case string(model.KindVulnerability):
			out = append(out, model.KindVulnerability)
		case string(model.KindMalware):
			out = append(out, model.KindMalware)
		}
	}
	return out
}
