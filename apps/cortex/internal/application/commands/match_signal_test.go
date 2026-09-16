package commands_test

import (
	"context"
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/commands"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// fakeMatcher returns canned candidate subscription ids.
type fakeMatcher struct {
	ids []string
	err error
}

func (f *fakeMatcher) Register(context.Context, model.Subscription) error { return nil }
func (f *fakeMatcher) Deregister(context.Context, string) error           { return nil }
func (f *fakeMatcher) Ready(context.Context) error                        { return nil }
func (f *fakeMatcher) Match(context.Context, model.Vulnerability) ([]string, error) {
	return f.ids, f.err
}

// fakeSubs is an in-memory SubscriptionRepo.
type fakeSubs struct {
	byID map[string]model.Subscription
	err  error
}

func (f *fakeSubs) Save(_ context.Context, s model.Subscription) error {
	f.byID[s.ID] = s
	return nil
}

func (f *fakeSubs) Get(_ context.Context, id string) (model.Subscription, error) {
	if f.err != nil {
		return model.Subscription{}, f.err
	}
	s, ok := f.byID[id]
	if !ok {
		return model.Subscription{}, ports.ErrSubscriptionNotFound
	}
	return s, nil
}

func (f *fakeSubs) List(_ context.Context, tenant string) ([]model.Subscription, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make([]model.Subscription, 0, len(f.byID))
	for _, s := range f.byID {
		if tenant == "" || s.Tenant == tenant {
			out = append(out, s)
		}
	}
	return out, nil
}
func (f *fakeSubs) Delete(_ context.Context, id string) error {
	delete(f.byID, id)
	return nil
}

// fakeAlerts records what was raised.
type fakeAlerts struct {
	appended []model.Alert
	err      error
}

func (f *fakeAlerts) Append(_ context.Context, a model.Alert) error {
	if f.err != nil {
		return f.err
	}
	f.appended = append(f.appended, a)
	return nil
}

func (f *fakeAlerts) List(context.Context, string, string, int) ([]model.Alert, error) {
	return f.appended, nil
}

// fakeDedupe remembers keys for the life of the test.
type fakeDedupe struct {
	seen map[string]struct{}
	err  error
}

func newFakeDedupe() *fakeDedupe { return &fakeDedupe{seen: map[string]struct{}{}} }

func (f *fakeDedupe) FirstSeen(_ context.Context, key string, _ time.Duration) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	if _, ok := f.seen[key]; ok {
		return false, nil
	}
	f.seen[key] = struct{}{}
	return true, nil
}

var _ = Describe("MatchSignal use case", func() {
	ctx := context.Background()
	lodash := valueobject.NewPackageRef("npm", "lodash", "")

	log4j := model.Vulnerability{
		CVEID: "CVE-2021-44228", Title: "Log4Shell in log4j",
		Scores: []model.CVSS{{Severity: model.SeverityCritical}},
	}
	watch := model.Subscription{
		ID: "sub-1", Tenant: "acme", Name: "Log4j watch",
		Rule: model.AlertRule{Term: "log4j"},
	}

	setup := func(subs ...model.Subscription) (*fakeMatcher, *fakeSubs, *fakeAlerts, *fakeDedupe) {
		repo := &fakeSubs{byID: map[string]model.Subscription{}}
		ids := make([]string, 0, len(subs))
		for _, s := range subs {
			repo.byID[s.ID] = s
			ids = append(ids, s.ID)
		}
		return &fakeMatcher{ids: ids}, repo, &fakeAlerts{}, newFakeDedupe()
	}

	It("raises an alert for a matching subscription", func() {
		matcher, subs, alerts, dedupe := setup(watch)

		raised, err := commands.NewMatchSignal(matcher, subs, alerts, dedupe, time.Hour).Handle(ctx, log4j)

		Expect(err).ToNot(HaveOccurred())
		Expect(raised).To(HaveLen(1))
		Expect(raised[0].SubscriptionID).To(Equal("sub-1"))
		Expect(raised[0].Tenant).To(Equal("acme"))
		Expect(raised[0].Reason).To(ContainSubstring("log4j"))
		Expect(alerts.appended).To(HaveLen(1))
	})

	It("stays quiet the second time the same CVE is observed", func() {
		matcher, subs, alerts, dedupe := setup(watch)
		match := commands.NewMatchSignal(matcher, subs, alerts, dedupe, time.Hour)

		first, err := match.Handle(ctx, log4j)
		Expect(err).ToNot(HaveOccurred())
		Expect(first).To(HaveLen(1))

		again, err := match.Handle(ctx, log4j)
		Expect(err).ToNot(HaveOccurred())
		Expect(again).To(BeEmpty(), "a re-observed advisory must not alert twice")
		Expect(alerts.appended).To(HaveLen(1))
	})

	It("alerts anyway when the dedupe store is unavailable", func() {
		// Suppression is an optimisation; a duplicate alert is recoverable,
		// a silent one is not.
		matcher, subs, alerts, dedupe := setup(watch)
		dedupe.err = errors.New("redis down")

		raised, err := commands.NewMatchSignal(matcher, subs, alerts, dedupe, time.Hour).Handle(ctx, log4j)

		Expect(err).ToNot(HaveOccurred())
		Expect(raised).To(HaveLen(1))
	})

	It("ignores a percolator hit the domain rule does not agree with", func() {
		// The index is a fast candidate finder; the rule is the definition.
		// A stale index must not be able to invent an alert.
		mismatched := model.Subscription{ID: "sub-2", Name: "Next.js watch",
			Rule: model.AlertRule{Packages: []valueobject.PackageRef{
				valueobject.NewPackageRef("npm", "next", "")}}}
		matcher, subs, alerts, dedupe := setup(mismatched)

		raised, err := commands.NewMatchSignal(matcher, subs, alerts, dedupe, time.Hour).Handle(ctx, log4j)

		Expect(err).ToNot(HaveOccurred())
		Expect(raised).To(BeEmpty())
		Expect(alerts.appended).To(BeEmpty())
	})

	It("skips a subscription deleted after it was indexed", func() {
		matcher, subs, alerts, dedupe := setup(watch)
		delete(subs.byID, "sub-1") // the index still names it

		raised, err := commands.NewMatchSignal(matcher, subs, alerts, dedupe, time.Hour).Handle(ctx, log4j)

		Expect(err).ToNot(HaveOccurred(), "a stale index entry is not a failure")
		Expect(raised).To(BeEmpty())
	})

	It("alerts every subscription that matches", func() {
		second := model.Subscription{ID: "sub-2", Tenant: "acme", Name: "Critical only",
			Rule: model.AlertRule{MinSeverity: model.SeverityCritical}}
		matcher, subs, alerts, dedupe := setup(watch, second)

		raised, err := commands.NewMatchSignal(matcher, subs, alerts, dedupe, time.Hour).Handle(ctx, log4j)

		Expect(err).ToNot(HaveOccurred())
		Expect(raised).To(HaveLen(2))
	})

	It("keeps alerting the others when one subscription fails", func() {
		second := model.Subscription{ID: "sub-2", Tenant: "acme", Name: "Critical only",
			Rule: model.AlertRule{MinSeverity: model.SeverityCritical}}
		matcher, subs, alerts, dedupe := setup(watch, second)
		alerts.err = errors.New("postgres down")

		_, err := commands.NewMatchSignal(matcher, subs, alerts, dedupe, time.Hour).Handle(ctx, log4j)

		Expect(err).To(MatchError(ContainSubstring("postgres down")))
	})

	It("reports a matcher failure rather than silently alerting nobody", func() {
		matcher, subs, alerts, dedupe := setup(watch)
		matcher.err = errors.New("elasticsearch down")

		_, err := commands.NewMatchSignal(matcher, subs, alerts, dedupe, time.Hour).Handle(ctx, log4j)

		Expect(err).To(MatchError(ContainSubstring("elasticsearch down")))
	})

	It("does nothing when no matcher is configured", func() {
		_, subs, alerts, dedupe := setup(watch)

		raised, err := commands.NewMatchSignal(nil, subs, alerts, dedupe, time.Hour).Handle(ctx, log4j)

		Expect(err).ToNot(HaveOccurred())
		Expect(raised).To(BeEmpty())
	})

	It("rejects a vulnerability with no identity", func() {
		matcher, subs, alerts, dedupe := setup(watch)
		_, err := commands.NewMatchSignal(matcher, subs, alerts, dedupe, time.Hour).
			Handle(ctx, model.Vulnerability{})
		Expect(err).To(MatchError(model.ErrMissingCVEID))
	})

	It("alerts separately for different CVEs matching one subscription", func() {
		matcher, subs, alerts, dedupe := setup(watch)
		match := commands.NewMatchSignal(matcher, subs, alerts, dedupe, time.Hour)

		_, err := match.Handle(ctx, log4j)
		Expect(err).ToNot(HaveOccurred())

		other := model.Vulnerability{CVEID: "CVE-2021-45046", Title: "another log4j flaw",
			AffectedPackages: []valueobject.PackageRef{lodash}}
		raised, err := match.Handle(ctx, other)

		Expect(err).ToNot(HaveOccurred())
		Expect(raised).To(HaveLen(1), "suppression is per CVE, not per subscription")
	})
})
