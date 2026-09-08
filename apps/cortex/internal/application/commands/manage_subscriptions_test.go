package commands_test

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/commands"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
)

// recordingMatcher tracks registrations so the index can be asserted on.
type recordingMatcher struct {
	registered   map[string]model.Subscription
	deregistered []string
	registerErr  error
	deregErr     error
}

func newRecordingMatcher() *recordingMatcher {
	return &recordingMatcher{registered: map[string]model.Subscription{}}
}

func (m *recordingMatcher) Register(_ context.Context, s model.Subscription) error {
	if m.registerErr != nil {
		return m.registerErr
	}
	m.registered[s.ID] = s
	return nil
}

func (m *recordingMatcher) Deregister(_ context.Context, id string) error {
	if m.deregErr != nil {
		return m.deregErr
	}
	m.deregistered = append(m.deregistered, id)
	delete(m.registered, id)
	return nil
}

func (m *recordingMatcher) Match(context.Context, model.Vulnerability) ([]string, error) {
	return nil, nil
}
func (m *recordingMatcher) Ready(context.Context) error { return nil }

var _ = Describe("ManageSubscriptions use case", func() {
	ctx := context.Background()
	rule := model.AlertRule{Term: "log4j"}

	It("stores a subscription and makes it matchable", func() {
		repo := &fakeSubs{byID: map[string]model.Subscription{}}
		matcher := newRecordingMatcher()

		sub, err := commands.NewManageSubscriptions(repo, matcher).Create(ctx, "acme", "Log4j watch", rule)

		Expect(err).ToNot(HaveOccurred())
		Expect(sub.ID).To(HavePrefix("sub_"))
		Expect(sub.Tenant).To(Equal("acme"))
		Expect(sub.CreatedAt).ToNot(BeZero())
		Expect(repo.byID).To(HaveKey(sub.ID))
		Expect(matcher.registered).To(HaveKey(sub.ID))
	})

	It("defaults the tenant when none is given", func() {
		repo := &fakeSubs{byID: map[string]model.Subscription{}}
		sub, err := commands.NewManageSubscriptions(repo, newRecordingMatcher()).
			Create(ctx, "", "Log4j watch", rule)

		Expect(err).ToNot(HaveOccurred())
		Expect(sub.Tenant).To(Equal(model.DefaultTenant))
	})

	It("rejects a rule that would match everything", func() {
		repo := &fakeSubs{byID: map[string]model.Subscription{}}
		_, err := commands.NewManageSubscriptions(repo, newRecordingMatcher()).
			Create(ctx, "acme", "everything", model.AlertRule{})

		Expect(err).To(MatchError(model.ErrEmptyAlertRule))
		Expect(repo.byID).To(BeEmpty())
	})

	It("rejects an unnamed subscription", func() {
		repo := &fakeSubs{byID: map[string]model.Subscription{}}
		_, err := commands.NewManageSubscriptions(repo, newRecordingMatcher()).
			Create(ctx, "acme", "  ", rule)

		Expect(err).To(MatchError(model.ErrMissingSubscriptionName))
	})

	It("rolls back rather than leaving a subscription that never fires", func() {
		// A stored-but-unindexed rule looks healthy in a listing and silently
		// never matches — worse than a create that visibly failed.
		repo := &fakeSubs{byID: map[string]model.Subscription{}}
		matcher := newRecordingMatcher()
		matcher.registerErr = errors.New("elasticsearch down")

		_, err := commands.NewManageSubscriptions(repo, matcher).Create(ctx, "acme", "Log4j watch", rule)

		Expect(err).To(MatchError(ContainSubstring("elasticsearch down")))
		Expect(repo.byID).To(BeEmpty(), "the half-created subscription must not survive")
	})

	It("gives every subscription an unguessable id", func() {
		repo := &fakeSubs{byID: map[string]model.Subscription{}}
		manage := commands.NewManageSubscriptions(repo, newRecordingMatcher())

		first, err := manage.Create(ctx, "acme", "one", rule)
		Expect(err).ToNot(HaveOccurred())
		second, err := manage.Create(ctx, "acme", "two", rule)
		Expect(err).ToNot(HaveOccurred())

		Expect(first.ID).ToNot(Equal(second.ID))
		Expect(len(first.ID)).To(BeNumerically(">", 20), "ids must not be enumerable")
	})

	It("removes a subscription from the index and from storage", func() {
		repo := &fakeSubs{byID: map[string]model.Subscription{}}
		matcher := newRecordingMatcher()
		manage := commands.NewManageSubscriptions(repo, matcher)

		sub, err := manage.Create(ctx, "acme", "Log4j watch", rule)
		Expect(err).ToNot(HaveOccurred())
		Expect(manage.Delete(ctx, sub.ID)).To(Succeed())

		Expect(repo.byID).To(BeEmpty())
		Expect(matcher.registered).To(BeEmpty())
		Expect(matcher.deregistered).To(ConsistOf(sub.ID))
	})

	It("keeps the rule stored when it cannot be removed from the index", func() {
		// Deleting storage first would leave alerts naming a subscription
		// nobody can look up.
		repo := &fakeSubs{byID: map[string]model.Subscription{}}
		matcher := newRecordingMatcher()
		manage := commands.NewManageSubscriptions(repo, matcher)
		sub, err := manage.Create(ctx, "acme", "Log4j watch", rule)
		Expect(err).ToNot(HaveOccurred())

		matcher.deregErr = errors.New("elasticsearch down")
		Expect(manage.Delete(ctx, sub.ID)).To(HaveOccurred())
		Expect(repo.byID).To(HaveKey(sub.ID))
	})

	It("requires an id to delete", func() {
		repo := &fakeSubs{byID: map[string]model.Subscription{}}
		Expect(commands.NewManageSubscriptions(repo, newRecordingMatcher()).Delete(ctx, "")).
			To(MatchError(ContainSubstring("id is required")))
	})

	It("rebuilds the index from storage", func() {
		// Postgres is the source of truth; the index can always be rebuilt.
		repo := &fakeSubs{byID: map[string]model.Subscription{
			"sub-1": {ID: "sub-1", Tenant: "acme", Name: "a", Rule: rule},
			"sub-2": {ID: "sub-2", Tenant: "acme", Name: "b", Rule: rule},
		}}
		matcher := newRecordingMatcher()

		n, err := commands.NewManageSubscriptions(repo, matcher).Reindex(ctx)

		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(2))
	})
})
