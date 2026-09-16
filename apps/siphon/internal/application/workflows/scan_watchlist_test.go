package workflows_test

import (
	"context"
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/application/workflows"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
)

// fakeWatchlist serves a fixed watchlist and records reports.
type fakeWatchlist struct {
	tracked []model.TrackedRepository
	listErr error
	reports []model.ScanOutcome
}

func (f *fakeWatchlist) Tracked(context.Context) ([]model.TrackedRepository, error) {
	return f.tracked, f.listErr
}

func (f *fakeWatchlist) ReportScan(_ context.Context, o model.ScanOutcome) error {
	f.reports = append(f.reports, o)
	return nil
}

var _ = Describe("ScanWatchlist use case", func() {
	var (
		ctx    = context.Background()
		rescan = 6 * time.Hour
		retry  = 15 * time.Minute
	)

	It("scans only what is due, and reports every outcome", func() {
		list := &fakeWatchlist{tracked: []model.TrackedRepository{
			{Owner: "vercel", Name: "next.js", Status: model.ScanPending},
			{Owner: "vercel", Name: "swr", Status: model.ScanScanned, LastScanAt: time.Now().Add(-time.Hour)},
			{Owner: "eslint", Name: "eslint", Status: model.ScanScanned, LastScanAt: time.Now().Add(-7 * time.Hour)},
			{Owner: "broken", Name: "repo", Status: model.ScanPending},
		}}
		client := &fakeRepoClient{
			snapshots: map[string]model.RepositorySnapshot{
				"vercel/next.js": snapshotFor("vercel", "next.js", "a", "b"),
				"eslint/eslint":  snapshotFor("eslint", "eslint", "c"),
			},
			errs: map[string]error{"broken/repo": errors.New("404 not found")},
		}

		n, err := workflows.NewScanWatchlist(list, client, &fakePublisher{}, rescan, retry).Run(ctx, time.Time{})

		// A repository failing is its own reported state, not a failed pass.
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(3))
		Expect(client.scanned).To(ConsistOf("vercel/next.js", "eslint/eslint", "broken/repo"),
			"vercel/swr was scanned an hour ago and is not due")

		Expect(list.reports).To(HaveLen(3))
		byName := map[string]model.ScanOutcome{}
		for _, r := range list.reports {
			byName[r.FullName] = r
		}
		Expect(byName["vercel/next.js"].Succeeded).To(BeTrue())
		Expect(byName["vercel/next.js"].DependencyCount).To(Equal(2))
		Expect(byName["broken/repo"].Succeeded).To(BeFalse())
		Expect(byName["broken/repo"].Error).To(ContainSubstring("404"))
	})

	It("fails the pass only when the watchlist itself is unreachable", func() {
		list := &fakeWatchlist{listErr: errors.New("cortex down")}
		_, err := workflows.NewScanWatchlist(list, &fakeRepoClient{}, &fakePublisher{}, rescan, retry).Run(ctx, time.Time{})
		Expect(err).To(MatchError(ContainSubstring("cortex down")))
	})
})

var _ = Describe("TrackedRepository.DueForScan", func() {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	rescan, retry := 6*time.Hour, 15*time.Minute

	It("scans a pending repository at once", func() {
		Expect(model.TrackedRepository{Status: model.ScanPending}.DueForScan(now, rescan, retry)).To(BeTrue())
	})
	It("rescans a scanned repository only after the rescan interval", func() {
		fresh := model.TrackedRepository{Status: model.ScanScanned, LastScanAt: now.Add(-time.Hour)}
		stale := model.TrackedRepository{Status: model.ScanScanned, LastScanAt: now.Add(-7 * time.Hour)}
		Expect(fresh.DueForScan(now, rescan, retry)).To(BeFalse())
		Expect(stale.DueForScan(now, rescan, retry)).To(BeTrue())
	})
	It("retries a failed repository sooner, but not on every pass", func() {
		justFailed := model.TrackedRepository{Status: model.ScanFailed, LastScanAt: now.Add(-time.Minute)}
		failedEarlier := model.TrackedRepository{Status: model.ScanFailed, LastScanAt: now.Add(-20 * time.Minute)}
		Expect(justFailed.DueForScan(now, rescan, retry)).To(BeFalse())
		Expect(failedEarlier.DueForScan(now, rescan, retry)).To(BeTrue())
	})
})
