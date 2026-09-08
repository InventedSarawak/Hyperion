package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

// DefaultDedupeWindow is how long the same subscription stays quiet about the
// same CVE. Advisories are re-observed on every poll and corrected for weeks;
// without a window a subscriber would hear about one finding dozens of times.
const DefaultDedupeWindow = time.Hour

// MatchSignal is reverse search: given one incoming vulnerability, find every
// subscription that wants to hear about it and raise an alert.
type MatchSignal struct {
	matcher ports.AlertMatcher
	subs    ports.SubscriptionRepo
	alerts  ports.AlertRepo
	dedupe  ports.DedupeStore
	window  time.Duration
	now     func() time.Time
	log     *slog.Logger
}

// NewMatchSignal wires the use case with its outbound ports. A nil dedupe
// store means every match raises an alert.
func NewMatchSignal(
	matcher ports.AlertMatcher,
	subs ports.SubscriptionRepo,
	alerts ports.AlertRepo,
	dedupe ports.DedupeStore,
	window time.Duration,
) *MatchSignal {
	if window <= 0 {
		window = DefaultDedupeWindow
	}
	return &MatchSignal{
		matcher: matcher, subs: subs, alerts: alerts, dedupe: dedupe,
		window: window, now: time.Now, log: slog.Default(),
	}
}

// Handle finds the subscriptions a vulnerability matches and records an alert
// for each, returning the alerts actually raised.
//
// One subscription failing does not silence the others: errors are collected
// and returned together, after every candidate has been attempted.
func (c *MatchSignal) Handle(ctx context.Context, v model.Vulnerability) ([]model.Alert, error) {
	if err := v.Validate(); err != nil {
		return nil, err
	}
	if c.matcher == nil {
		return nil, nil
	}

	candidates, err := c.matcher.Match(ctx, v)
	if err != nil {
		return nil, fmt.Errorf("match %s: %w", v.CVEID, err)
	}

	var (
		raised []model.Alert
		errs   []error
	)
	for _, id := range candidates {
		alert, ok, err := c.raise(ctx, id, v)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if ok {
			raised = append(raised, alert)
		}
	}
	return raised, errors.Join(errs...)
}

// raise turns one candidate subscription into an alert, reporting whether one
// was actually recorded.
func (c *MatchSignal) raise(ctx context.Context, subscriptionID string, v model.Vulnerability) (model.Alert, bool, error) {
	sub, err := c.subs.Get(ctx, subscriptionID)
	switch {
	case errors.Is(err, ports.ErrSubscriptionNotFound):
		// Deleted between being indexed and being matched. Not an error, but
		// the index is now stale, so say so rather than failing silently.
		c.log.Warn("matched a subscription that no longer exists; percolator index is stale",
			"subscription", subscriptionID, "cve", v.CVEID)
		return model.Alert{}, false, nil
	case err != nil:
		return model.Alert{}, false, fmt.Errorf("load subscription %s: %w", subscriptionID, err)
	}

	// The percolator is an index, not the definition of a match. Re-checking
	// against the domain rule means a stale or over-broad index cannot invent
	// an alert — the cost of a false alert here is a subscriber who stops
	// trusting alerts entirely.
	if !sub.Rule.Matches(v) {
		c.log.Warn("percolator matched a rule the domain does not; ignoring",
			"subscription", subscriptionID, "cve", v.CVEID)
		return model.Alert{}, false, nil
	}

	alert := model.NewAlert(sub, v, c.now())

	if c.dedupe != nil {
		first, err := c.dedupe.FirstSeen(ctx, alert.DedupeKey(), c.window)
		if err != nil {
			// Suppression is an optimisation; losing it must not lose the
			// alert. Better a duplicate than a silence.
			c.log.Warn("dedupe unavailable; alerting without suppression",
				"subscription", subscriptionID, "cve", v.CVEID, "error", err)
		} else if !first {
			return model.Alert{}, false, nil
		}
	}

	if err := c.alerts.Append(ctx, alert); err != nil {
		return model.Alert{}, false, fmt.Errorf("record alert %s: %w", alert.ID, err)
	}

	c.log.Info("alert raised",
		"subscription", sub.Name, "tenant", sub.Tenant, "cve", v.CVEID, "reason", alert.Reason)
	return alert, true, nil
}
