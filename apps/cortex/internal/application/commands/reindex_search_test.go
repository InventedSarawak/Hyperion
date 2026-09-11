package commands_test

import (
	"context"
	"errors"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/application/commands"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
)

// failingIndex fails on one id, to prove the walk stops and reports it.
type failingIndex struct {
	memIndex
	failOn string
}

func (f *failingIndex) Index(ctx context.Context, v model.Vulnerability) error {
	if v.CVEID == f.failOn {
		return errors.New("elasticsearch down")
	}
	return f.memIndex.Index(ctx, v)
}

var _ = Describe("ReindexSearch use case", func() {
	ctx := context.Background()

	fill := func(n int) *memRepo {
		repo := newMemRepo()
		for i := 0; i < n; i++ {
			id := fmt.Sprintf("CVE-2026-%05d", i)
			repo.store[id] = model.Vulnerability{CVEID: id}
		}
		return repo
	}

	It("re-indexes every stored record, across many batches", func() {
		// 1,234 records is more than two batches of 500, so the keyset walk
		// has to carry its position from one page to the next.
		repo, index := fill(1234), &memIndex{}

		report, err := commands.NewReindexSearch(repo, index).Run(ctx)

		Expect(err).ToNot(HaveOccurred())
		Expect(report.Written).To(Equal(1234))
		Expect(index.indexed).To(HaveLen(1234))

		seen := map[string]bool{}
		for _, v := range index.indexed {
			Expect(seen).ToNot(HaveKey(v.CVEID), "no record indexed twice")
			seen[v.CVEID] = true
		}
	})

	It("does nothing, successfully, when the store is empty", func() {
		report, err := commands.NewReindexSearch(newMemRepo(), &memIndex{}).Run(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(report).To(Equal(commands.Report{}))
	})

	It("stops at the first failure and says where", func() {
		index := &failingIndex{failOn: "CVE-2026-00600"}
		report, err := commands.NewReindexSearch(fill(1000), index).Run(ctx)

		Expect(err).To(MatchError(ContainSubstring("CVE-2026-00600")))
		Expect(report.Written).To(Equal(600), "everything before the failure was written")
	})

	It("refuses to run without a search index", func() {
		_, err := commands.NewReindexSearch(newMemRepo(), nil).Run(ctx)
		Expect(err).To(MatchError(ContainSubstring("no search index")))
	})
})

var _ = Describe("ReindexSearch reconciliation", func() {
	ctx := context.Background()

	It("removes documents that have no record in Postgres", func() {
		repo := newMemRepo()
		repo.store["CVE-KEEP"] = model.Vulnerability{CVEID: "CVE-KEEP"}
		index := &memIndex{extra: []string{"CVE-ORPHAN-1", "CVE-ORPHAN-2"}}

		report, err := commands.NewReindexSearch(repo, index).Run(ctx)

		Expect(err).ToNot(HaveOccurred())
		Expect(report.Written).To(Equal(1))
		Expect(report.Removed).To(Equal(2))
		Expect(index.deleted).To(ConsistOf("CVE-ORPHAN-1", "CVE-ORPHAN-2"))
	})

	It("keeps a record ingested while the reindex was running", func() {
		// The walk never saw it, so it is not in the written set — but it is
		// in Postgres, and deleting it would lose a real finding from search.
		repo := newMemRepo()
		repo.store["CVE-OLD"] = model.Vulnerability{CVEID: "CVE-OLD"}
		index := &memIndex{extra: []string{"CVE-ARRIVED-LATE"}}
		repo.store["CVE-ARRIVED-LATE"] = model.Vulnerability{CVEID: "CVE-ARRIVED-LATE"}
		// Simulate "arrived after the walk passed it": the walk only sees ids
		// up to where it has got, so remove it from what Scan will return.
		late := &lateRepo{memRepo: repo, hidden: "CVE-ARRIVED-LATE"}

		report, err := commands.NewReindexSearch(late, index).Run(ctx)

		Expect(err).ToNot(HaveOccurred())
		Expect(report.Removed).To(Equal(0))
		Expect(index.deleted).To(BeEmpty())
	})
})

// lateRepo hides one record from Scan — as if it was written after the walk
// had passed its position — while still answering GetByCVE for it.
type lateRepo struct {
	*memRepo
	hidden string
}

func (l *lateRepo) Scan(ctx context.Context, after string, limit int) ([]model.Vulnerability, error) {
	page, err := l.memRepo.Scan(ctx, after, limit)
	out := page[:0]
	for _, v := range page {
		if v.CVEID != l.hidden {
			out = append(out, v)
		}
	}
	return out, err
}
