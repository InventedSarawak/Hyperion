package commands_test

import (
	"context"
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/commands"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
)

// fakeReconciler stands in for the store's view of what is behind.
type fakeReconciler struct {
	behind   []model.Vulnerability
	marked   []string
	markedAt time.Time
	readErr  error
	markErr  error
}

func (f *fakeReconciler) PendingIndex(_ context.Context, limit int) ([]model.Vulnerability, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	if limit > 0 && len(f.behind) > limit {
		return f.behind[:limit], nil
	}
	return f.behind, nil
}

func (f *fakeReconciler) MarkIndexed(_ context.Context, at time.Time, ids ...string) error {
	if f.markErr != nil {
		return f.markErr
	}
	f.marked = append(f.marked, ids...)
	f.markedAt = at
	return nil
}

// refusingIndex accepts the first failAt records and refuses everything after,
// which is how an index that has started rejecting writes behaves.
type refusingIndex struct {
	indexed []string
	failAt  int
}

func (f *refusingIndex) Index(_ context.Context, v model.Vulnerability) error {
	if f.failAt > 0 && len(f.indexed) >= f.failAt {
		return errors.New("elasticsearch is refusing writes")
	}
	f.indexed = append(f.indexed, v.CVEID)
	return nil
}

func (f *refusingIndex) Delete(context.Context, string) error { return nil }
func (f *refusingIndex) Ready(context.Context) error          { return nil }
func (f *refusingIndex) IDs(context.Context) ([]string, error) {
	return append([]string(nil), f.indexed...), nil
}

func (f *refusingIndex) Search(context.Context, model.SearchQuery) (model.SearchPage, error) {
	return model.SearchPage{}, nil
}

var _ = Describe("ReconcileIndex", func() {
	var ctx = context.Background()

	It("writes the records that are behind and marks them settled", func() {
		store := &fakeReconciler{behind: []model.Vulnerability{
			{CVEID: "CVE-2021-44228"}, {CVEID: "CVE-2021-45046"},
		}}
		index := &refusingIndex{}

		n, err := commands.NewReconcileIndex(store, index).Run(ctx)

		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(2))
		Expect(index.indexed).To(Equal([]string{"CVE-2021-44228", "CVE-2021-45046"}))
		Expect(store.marked).To(Equal([]string{"CVE-2021-44228", "CVE-2021-45046"}))
	})

	It("does nothing when nothing is behind, which is the normal state", func() {
		store := &fakeReconciler{}
		index := &refusingIndex{}

		n, err := commands.NewReconcileIndex(store, index).Run(ctx)

		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(BeZero())
		Expect(index.indexed).To(BeEmpty())
	})

	It("stops at the first failure and leaves the rest marked for the next pass", func() {
		store := &fakeReconciler{behind: []model.Vulnerability{
			{CVEID: "CVE-1"}, {CVEID: "CVE-2"}, {CVEID: "CVE-3"},
		}}
		index := &refusingIndex{failAt: 1}

		n, err := commands.NewReconcileIndex(store, index).Run(ctx)

		// An index that has started refusing writes will refuse the rest too;
		// the records it did not take stay behind rather than being marked
		// settled, which is the only way they are ever repaired.
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(1))
		Expect(store.marked).To(Equal([]string{"CVE-1"}))
	})

	It("reports a store it cannot read", func() {
		store := &fakeReconciler{readErr: errors.New("postgres is down")}

		_, err := commands.NewReconcileIndex(store, &refusingIndex{}).Run(ctx)

		Expect(err).To(MatchError(ContainSubstring("read pending")))
	})

	It("does nothing when there is no index to reconcile against", func() {
		store := &fakeReconciler{behind: []model.Vulnerability{{CVEID: "CVE-1"}}}

		n, err := commands.NewReconcileIndex(store, nil).Run(ctx)

		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(BeZero())
	})
})
