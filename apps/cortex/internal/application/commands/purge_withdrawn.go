package commands

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

// PurgeWithdrawn removes findings that were stored before their retraction was
// noticed.
//
// It exists because the check came late. NVD marks a disowned id with
// `vulnStatus: Rejected`, which siphon now reads and reports — but every record
// ingested before that was stored as an ordinary finding, and most of them will
// never be modified again, so no future observation will come along to correct
// them.
//
// Retractions are recognised by the description, which is the only evidence
// those stored rows carry: NVD replaces a rejected record's description with a
// "Rejected reason:" note, or the older "** REJECT **" marker. That is a
// heuristic, and it is deliberately confined to this one-off pass — live
// ingestion uses the status field, which is the authoritative answer.
type PurgeWithdrawn struct {
	repo   ports.VulnerabilityRepo
	ingest *IngestSignal
	batch  int
	log    *slog.Logger
	// dryRun reports what would go without removing anything.
	dryRun bool
}

// DryRun counts what would be removed and removes nothing. Deleting tens of
// thousands of rows on the strength of a heuristic deserves a look first.
func (c *PurgeWithdrawn) DryRun() *PurgeWithdrawn {
	c.dryRun = true
	return c
}

// NewPurgeWithdrawn wires the use case. Withdrawal goes through IngestSignal so
// the record leaves Postgres, the search index and the graph by exactly the
// same path a live retraction takes.
func NewPurgeWithdrawn(repo ports.VulnerabilityRepo, ingest *IngestSignal) *PurgeWithdrawn {
	return &PurgeWithdrawn{repo: repo, ingest: ingest, batch: 500, log: slog.Default()}
}

// Run walks every stored finding and withdraws the retracted ones, reporting
// how many were removed.
func (c *PurgeWithdrawn) Run(ctx context.Context) (int, error) {
	removed, after := 0, ""
	for {
		batch, err := c.repo.Scan(ctx, after, c.batch)
		if err != nil {
			return removed, fmt.Errorf("purge withdrawn: read after %q: %w", after, err)
		}
		if len(batch) == 0 {
			return removed, nil
		}
		// Read before withdrawing: deleting rows while paging by key would
		// not lose the position (keyset paging survives deletes), but the
		// last id of the batch has to be remembered either way.
		after = batch[len(batch)-1].CVEID

		for _, v := range batch {
			if !IsRetracted(v) {
				continue
			}
			if c.dryRun {
				removed++
				c.log.Info("would withdraw", "cve", v.CVEID, "description", firstLine(v.Description))
				continue
			}
			if err := c.ingest.Handle(ctx, Observation{Vulnerability: v, Withdrawn: true}); err != nil {
				return removed, fmt.Errorf("purge withdrawn %s: %w", v.CVEID, err)
			}
			removed++
		}
		c.log.Info("purge progress", "removed", removed, "through", after)
	}
}

// retractionMarkers are how NVD writes a rejected record's description.
var retractionMarkers = []string{"** REJECT", "Rejected reason:"}

// IsRetracted reports whether a stored finding's description says it was
// disowned. Exported so the same rule can be asserted directly in tests.
func IsRetracted(v model.Vulnerability) bool {
	description := strings.TrimSpace(v.Description)
	for _, marker := range retractionMarkers {
		if strings.HasPrefix(description, marker) || strings.Contains(description, marker) {
			return true
		}
	}
	return false
}

// firstLine trims a description down to something a log line can carry.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 90 {
		s = s[:90] + "…"
	}
	return s
}
