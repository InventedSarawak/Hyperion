package sources

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// CheckResult is one source's outcome from a live connectivity probe.
type CheckResult struct {
	Kind     valueobject.SourceKind
	Name     string
	Active   bool
	Reason   string        // why inactive; empty when active
	Note     string        // e.g. running without an optional credential
	Fetched  int           // signals returned by the probe
	Duration time.Duration // how long the probe took
	Err      error         // probe failure, if any
}

// OK reports whether the source is active and answered without error.
func (r CheckResult) OK() bool { return r.Active && r.Err == nil }

// Check probes every active source with a real fetch over the given lookback,
// so an operator can confirm which feeds genuinely answer. Nothing is
// published: this is a read-only diagnostic.
//
// Sources are probed concurrently; each is independent, so one slow or broken
// feed cannot hide the others.
func (r *Registry) Check(ctx context.Context, lookback time.Duration) []CheckResult {
	results := make([]CheckResult, len(r.statuses))
	since := time.Now().Add(-lookback)

	done := make(chan int, len(r.statuses))
	for i, s := range r.statuses {
		results[i] = CheckResult{
			Kind: s.Kind, Name: s.Name, Active: s.Active, Reason: s.Reason, Note: s.Note,
		}
		if !s.Active || s.Client == nil {
			done <- i
			continue
		}

		go func(i int, status Status) {
			start := time.Now()
			signals, err := status.Client.Fetch(ctx, since)

			results[i].Fetched = len(signals)
			results[i].Duration = time.Since(start)
			results[i].Err = err
			done <- i
		}(i, s)
	}
	for range r.statuses {
		<-done
	}

	sort.SliceStable(results, func(a, b int) bool { return results[a].Kind < results[b].Kind })
	return results
}

// Summary renders a check run as a human-readable report.
func Summary(results []CheckResult) string {
	var (
		out     string
		active  int
		healthy int
	)
	out = fmt.Sprintf("%-18s %-9s %-8s %-9s %s\n", "SOURCE", "STATUS", "SIGNALS", "TOOK", "DETAIL")

	for _, r := range results {
		status, detail := "INACTIVE", r.Reason
		signals, took := "-", "-"

		switch {
		case !r.Active:
		case r.Err != nil:
			status, detail = "FAILED", truncate(r.Err.Error(), 68)
			took = r.Duration.Round(time.Millisecond).String()
			active++
		default:
			status, detail = "OK", r.Note
			signals = fmt.Sprint(r.Fetched)
			took = r.Duration.Round(time.Millisecond).String()
			active++
			healthy++
		}
		out += fmt.Sprintf("%-18s %-9s %-8s %-9s %s\n", r.Kind, status, signals, took, detail)
	}

	out += fmt.Sprintf("\n%d/%d sources active, %d answered successfully\n",
		active, len(results), healthy)
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
